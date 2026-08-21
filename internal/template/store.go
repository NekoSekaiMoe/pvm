// Package template implements a Template Center mirroring
// CubeMaster/pkg/templatecenter/store.go at single-host scale.
//
// Each template is a filesystem directory at
// /var/lib/uml-container/templates/<id>/ with meta.json (TemplateRecord)
// and the backing image file itself. List/GetByAlias are file-backed so
// they survive restarts without a DB.
package template

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"uml-container/internal/fsjson"
)

var idRe = regexp.MustCompile(`^(tpl|snap)-[a-f0-9]{24}$`)
var aliasRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

// Sentinel errors so callers (e.g. the REST layer) can classify failures
// with errors.Is instead of matching error strings:
//   - ErrInvalid / ErrConflict / ErrNotFound map to 400 / 409 / 404;
//     anything else is an underlying storage fault (500).
var (
	ErrInvalid  = errors.New("template: invalid input")
	ErrConflict = errors.New("template: conflict")
	ErrNotFound = errors.New("template: not found")
)

// Record mirrors CubeMaster templatecenter.TemplateInfo at the storage layer.
type Record struct {
	TemplateID  string    `json:"template_id"`
	Alias       string    `json:"alias,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	Kind        string    `json:"kind"`   // "template" | "snapshot"
	Status      string    `json:"status"` // "READY" | "PENDING" | "FAILED"
	ImageRef    string    `json:"image_ref,omitempty"`
	ImagePath   string    `json:"image_path,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Store is a file-backed template registry. It keeps an in-memory
// alias→templateID index (initialized from disk at construction and maintained
// by Create/SetAlias/Delete) so alias resolution is O(1) instead of scanning
// and parsing every meta.json.
type Store struct {
	mu      sync.Mutex
	root    string
	aliases map[string]string // alias -> templateID
}

func resolveRoot() string {
	if v := os.Getenv("PVM_TEMPLATE_ROOT"); v != "" {
		return v
	}
	return "/var/lib/uml-container/templates"
}

func NewStore(root string) *Store {
	if root == "" {
		root = resolveRoot()
	}
	s := &Store{root: root, aliases: make(map[string]string)}
	s.loadAliases()
	return s
}

// loadAliases populates the alias index from records already on disk so
// GetByAlias/ResolveIdentifier work immediately for pre-existing templates.
// Best-effort: on an unreadable root the index starts empty.
func (s *Store) loadAliases() {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.root, e.Name(), "meta.json"))
		if err != nil {
			continue
		}
		var rec Record
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		if rec.Alias != "" {
			if _, ok := s.aliases[rec.Alias]; !ok {
				s.aliases[rec.Alias] = rec.TemplateID
			}
		}
	}
}

func generateTemplateID() string {
	return "tpl-" + strings.ReplaceAll(uuid.New().String(), "-", "")[:24]
}

func generateSnapshotID() string {
	return "snap-" + strings.ReplaceAll(uuid.New().String(), "-", "")[:24]
}

// GenerateTemplateID is exported for callers that need an id before creation.
func GenerateTemplateID() string { return generateTemplateID() }

// GenerateSnapshotID is exported for snapshot callers.
func GenerateSnapshotID() string { return generateSnapshotID() }

func (s *Store) dir(id string) (string, error) {
	if !idRe.MatchString(id) {
		return "", fmt.Errorf("%w: invalid id %q", ErrInvalid, id)
	}
	return filepath.Join(s.root, id), nil
}

func validateAlias(alias string) error {
	if alias == "" {
		return nil
	}
	if !aliasRe.MatchString(alias) {
		return fmt.Errorf("%w: invalid alias %q (must match %s)", ErrInvalid, alias, aliasRe.String())
	}
	return nil
}

// Create inserts a new template record. Id must be "tpl-..." or "snap-...".
// Alias, if non-empty, must be unique among READY templates.
func (s *Store) Create(rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.TemplateID == "" {
		rec.TemplateID = generateTemplateID()
	}
	if !idRe.MatchString(rec.TemplateID) {
		return fmt.Errorf("%w: invalid id %q", ErrInvalid, rec.TemplateID)
	}
	if err := validateAlias(rec.Alias); err != nil {
		return err
	}
	if rec.Alias != "" {
		// uniqueness among all templates (mirrors alias_key unique index)
		existing, _ := s.getByAliasLocked(rec.Alias)
		if existing != nil {
			return fmt.Errorf("%w: alias %q already claimed by %s", ErrConflict, rec.Alias, existing.TemplateID)
		}
	}
	dir, _ := s.dir(rec.TemplateID)
	if _, err := os.Stat(filepath.Join(dir, "meta.json")); err == nil {
		return fmt.Errorf("%w: %q already exists", ErrConflict, rec.TemplateID)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	if rec.Status == "" {
		rec.Status = "READY"
	}
	if rec.Kind == "" {
		if strings.HasPrefix(rec.TemplateID, "snap-") {
			rec.Kind = "snapshot"
		} else {
			rec.Kind = "template"
		}
	}
	if err := writeMeta(dir, rec); err != nil {
		return err
	}
	if rec.Alias != "" {
		s.aliases[rec.Alias] = rec.TemplateID
	}
	return nil
}

// Get returns the record for id.
func (s *Store) Get(id string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(id)
}

func (s *Store) getLocked(id string) (*Record, error) {
	dir, err := s.dir(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetByAlias resolves an alias to its template record.
func (s *Store) GetByAlias(alias string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getByAliasLocked(alias)
}

func (s *Store) getByAliasLocked(alias string) (*Record, error) {
	if alias == "" {
		return nil, fmt.Errorf("%w: empty alias", ErrInvalid)
	}
	id, ok := s.aliases[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q", ErrNotFound, alias)
	}
	rec, err := s.getLocked(id)
	if err != nil {
		// Record vanished on disk (deleted externally); drop the stale entry.
		delete(s.aliases, alias)
		return nil, fmt.Errorf("%w: alias %q", ErrNotFound, alias)
	}
	return rec, nil
}

// ResolveIdentifier returns the template ID for either a raw id (tpl-/snap-)
// or an alias. Empty input returns ("", nil).
func (s *Store) ResolveIdentifier(identifier string) (string, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "", nil
	}
	if idRe.MatchString(identifier) {
		return identifier, nil
	}
	rec, err := s.GetByAlias(identifier)
	if err != nil {
		return "", err
	}
	return rec.TemplateID, nil
}

// SetAlias atomically claims or clears an alias. Mirrors
// templatecenter.SetTemplateAlias semantics: requireReady for claim.
func (s *Store) SetAlias(templateID, alias string) error {
	alias = strings.TrimSpace(alias)
	if err := validateAlias(alias); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.dir(templateID)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fmt.Errorf("%w: %q", ErrNotFound, templateID)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	if alias != "" && rec.Status != "READY" {
		return fmt.Errorf("%w: %q not ready (status=%s)", ErrConflict, templateID, rec.Status)
	}
	if alias != "" {
		existing, _ := s.getByAliasLocked(alias)
		if existing != nil && existing.TemplateID != templateID {
			return fmt.Errorf("%w: alias %q already claimed by %s", ErrConflict, alias, existing.TemplateID)
		}
	}
	oldAlias := rec.Alias
	rec.Alias = alias
	if err := writeMeta(dir, rec); err != nil {
		return err
	}
	if oldAlias != "" && s.aliases[oldAlias] == templateID {
		delete(s.aliases, oldAlias)
	}
	if alias != "" {
		s.aliases[alias] = templateID
	}
	return nil
}

// List returns all template records sorted by CreatedAt desc.
func (s *Store) List() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.root, e.Name(), "meta.json"))
		if err != nil {
			continue
		}
		var rec Record
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Delete removes the template directory and drops its alias index entry.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.dir(id)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if rec.Alias != "" && s.aliases[rec.Alias] == id {
		delete(s.aliases, rec.Alias)
	}
	return nil
}

func writeMeta(dir string, rec Record) error {
	return fsjson.Write(filepath.Join(dir, "meta.json"), rec)
}
