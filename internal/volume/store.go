package volume

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var volumeIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// VolumeRecord is the persisted metadata for one volume, mirroring
// CubeMaster/pkg/base/db/models/volume.go:VolumeRecord.
type VolumeRecord struct {
	VolumeID    string    `json:"volume_id"`
	Name        string    `json:"name"`
	Driver      string    `json:"driver"`
	Token       string    `json:"token,omitempty"`
	PrivateData string    `json:"private_data,omitempty"`
	RefCount    int       `json:"refcount"`
	CreatedAt   time.Time `json:"created_at"`
}

// volumeRoot is the on-disk root for volume records.
var volumeRoot = resolveVolumeRoot()

func resolveVolumeRoot() string {
	if v := os.Getenv("PVM_VOLUME_ROOT"); v != "" {
		return v
	}
	return "/var/lib/uml-container/volumes"
}

func volumeDir(id string) (string, error) {
	if !volumeIDRe.MatchString(id) {
		return "", fmt.Errorf("volume: invalid id %q (must match %s)", id, volumeIDRe.String())
	}
	return filepath.Join(volumeRoot, id), nil
}

// Store persists VolumeRecords as <volumeRoot>/<id>/meta.json.
type Store struct {
	mu sync.Mutex
}

func NewStore() *Store { return &Store{} }

// Create inserts a new record. Returns an error if the id already exists.
func (s *Store) Create(rec VolumeRecord) error {
	if !volumeIDRe.MatchString(rec.VolumeID) {
		return fmt.Errorf("volume: invalid id %q", rec.VolumeID)
	}
	if rec.Name == "" {
		rec.Name = rec.VolumeID
	}
	if !volumeIDRe.MatchString(rec.Name) {
		return fmt.Errorf("volume: invalid name %q", rec.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, _ := volumeDir(rec.VolumeID)
	if _, err := os.Stat(filepath.Join(dir, "meta.json")); err == nil {
		return fmt.Errorf("volume: %q already exists", rec.VolumeID)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	return writeMeta(dir, rec)
}

// Get returns the record for id or an error if not found.
func (s *Store) Get(id string) (*VolumeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := volumeDir(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("volume: not found %q", id)
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
	entries, err := os.ReadDir(volumeRoot)
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
		data, err := os.ReadFile(filepath.Join(volumeRoot, e.Name(), "meta.json"))
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
// (mirrors Cube's "409 when still mounted" guard).
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := volumeDir(id)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fmt.Errorf("volume: not found %q", id)
	}
	var rec VolumeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	if rec.RefCount != 0 {
		return fmt.Errorf("volume: %q still mounted (refcount=%d)", id, rec.RefCount)
	}
	return os.RemoveAll(dir)
}

// IncRef increments the file-persisted refcount (called on 0→1 attach).
func (s *Store) IncRef(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := volumeDir(id)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fmt.Errorf("volume: not found %q", id)
	}
	var rec VolumeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	rec.RefCount++
	return writeMeta(dir, rec)
}

// DecRef decrements the persisted refcount (called on 1→0 detach).
func (s *Store) DecRef(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := volumeDir(id)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fmt.Errorf("volume: not found %q", id)
	}
	var rec VolumeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	if rec.RefCount > 0 {
		rec.RefCount--
	}
	return writeMeta(dir, rec)
}

func writeMeta(dir string, rec VolumeRecord) error {
	tmp, err := os.CreateTemp(dir, ".meta-*.json.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rec); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	tmp.Close()
	return os.Rename(name, filepath.Join(dir, "meta.json"))
}
