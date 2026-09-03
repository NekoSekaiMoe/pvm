package volume

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"uml-container/internal/fsjson"
)

var volumeIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// ValidateID reports whether id is a valid volume/driver identifier. It is
// the exported form of the rule the store, Manager.Register, Attach and
// Detach all enforce, so callers that validate names BEFORE registration
// (e.g. agentpvm's PVM_VOLUME_PLUGINS parsing) share one rule instead of
// mirroring the unexported regexp.
func ValidateID(id string) bool {
	return volumeIDRe.MatchString(id)
}

// Sentinel errors so callers (e.g. the REST layer) can classify failures
// with errors.Is instead of matching error strings:
//   - ErrInvalid / ErrExists / ErrNotFound / ErrStillMounted map to
//     400 / 409 / 404 / 409 respectively; anything else is an underlying
//     storage fault (500).
var (
	ErrInvalid      = errors.New("volume: invalid input")
	ErrExists       = errors.New("volume: already exists")
	ErrNotFound     = errors.New("volume: not found")
	ErrStillMounted = errors.New("volume: still mounted")
)

// VolumeRecord is the persisted metadata for one volume, mirroring
// the persisted volume record.
type VolumeRecord struct {
	VolumeID    string    `json:"volume_id"`
	Name        string    `json:"name"`
	Driver      string    `json:"driver"`
	Token       string    `json:"token,omitempty"`
	PrivateData string    `json:"private_data,omitempty"`
	RefCount    int       `json:"refcount"`
	CreatedAt   time.Time `json:"created_at"`
}

// resolveVolumeRoot resolves the default volume root. It is overridable via
// PVM_VOLUME_ROOT and otherwise falls back to the shared DefaultVolumeBaseDir
// constant (defined in manager.go).
func resolveVolumeRoot() string {
	if v := os.Getenv("PVM_VOLUME_ROOT"); v != "" {
		return v
	}
	return DefaultVolumeBaseDir
}

// Store persists VolumeRecords as <root>/<id>/meta.json.
type Store struct {
	mu   sync.Mutex
	root string
}

// NewStore creates a Store rooted at root. An empty root falls back to
// resolveVolumeRoot (PVM_VOLUME_ROOT / DefaultVolumeBaseDir).
func NewStore(root string) *Store {
	if root == "" {
		root = resolveVolumeRoot()
	}
	return &Store{root: root}
}

// volumeDir validates id and returns the record directory under s.root.
func (s *Store) volumeDir(id string) (string, error) {
	if !volumeIDRe.MatchString(id) {
		return "", fmt.Errorf("%w: invalid id %q (must match %s)", ErrInvalid, id, volumeIDRe.String())
	}
	return filepath.Join(s.root, id), nil
}

// Create inserts a new record. Returns an error if the id already exists.
func (s *Store) Create(rec VolumeRecord) error {
	if !volumeIDRe.MatchString(rec.VolumeID) {
		return fmt.Errorf("%w: invalid id %q", ErrInvalid, rec.VolumeID)
	}
	if rec.Name == "" {
		rec.Name = rec.VolumeID
	}
	if !volumeIDRe.MatchString(rec.Name) {
		return fmt.Errorf("%w: invalid name %q", ErrInvalid, rec.Name)
	}
	if rec.RefCount < 0 {
		return fmt.Errorf("%w: negative refcount %d", ErrInvalid, rec.RefCount)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.volumeDir(rec.VolumeID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "meta.json")); err == nil {
		return fmt.Errorf("%w: %q", ErrExists, rec.VolumeID)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	writeErr := writeMeta(dir, rec)
	if writeErr != nil {
		if !errors.Is(writeErr, fsjson.ErrDurability) {
			return writeErr
		}
		// The rename was committed; only the durability confirmation failed.
		// Re-read the on-disk record: if it matches, the Create succeeded.
		data, rerr := os.ReadFile(filepath.Join(dir, "meta.json"))
		if rerr != nil {
			return writeErr
		}
		var got VolumeRecord
		if json.Unmarshal(data, &got) != nil || got.VolumeID != rec.VolumeID {
			return writeErr
		}
	}
	return nil
}

// Get returns the record for id or an error if not found.
func (s *Store) Get(id string) (*VolumeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.volumeDir(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	var rec VolumeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// List returns all volume records sorted by CreatedAt.
func (s *Store) List() ([]VolumeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []VolumeRecord
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.root, e.Name(), "meta.json"))
		if err != nil {
			continue
		}
		var rec VolumeRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// Delete removes the volume directory. Returns an error if refcount != 0
// (409 while still mounted).
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.volumeDir(id)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	var rec VolumeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	if rec.RefCount != 0 {
		return fmt.Errorf("%w: %q (refcount=%d)", ErrStillMounted, id, rec.RefCount)
	}
	return os.RemoveAll(dir)
}

// IncRef increments the file-persisted refcount (called on 0→1 attach).
func (s *Store) IncRef(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.volumeDir(id)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	var rec VolumeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	rec.RefCount++
	return s.commitRefCount(dir, rec)
}

// DecRef decrements the persisted refcount (called on 1→0 detach).
func (s *Store) DecRef(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.volumeDir(id)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	var rec VolumeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	if rec.RefCount > 0 {
		rec.RefCount--
	}
	return s.commitRefCount(dir, rec)
}

// commitRefCount persists a RefCount change and reconciles the fsjson
// durability condition: when the rename committed but the durability
// confirmation failed, re-read the record and treat the change as applied
// only if the on-disk refcount matches the intended value. Returning the
// error instead would make callers retry an already-applied increment or
// decrement and double-count.
func (s *Store) commitRefCount(dir string, rec VolumeRecord) error {
	if err := writeMeta(dir, rec); err != nil {
		if !errors.Is(err, fsjson.ErrDurability) {
			return err
		}
		data, rerr := os.ReadFile(filepath.Join(dir, "meta.json"))
		if rerr != nil {
			return err
		}
		var got VolumeRecord
		if json.Unmarshal(data, &got) != nil || got.VolumeID != rec.VolumeID || got.RefCount != rec.RefCount {
			return err
		}
	}
	return nil
}

// writeJSON is the atomic persistence primitive; a variable so tests can
// inject fsjson.ErrDurability (write committed, durability confirmation
// failed) and exercise the reconciliation paths in Create and IncRef/DecRef.
var writeJSON = fsjson.Write

func writeMeta(dir string, rec VolumeRecord) error {
	return writeJSON(filepath.Join(dir, "meta.json"), rec)
}
