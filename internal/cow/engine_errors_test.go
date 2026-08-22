package cow

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestEngineSentinelErrors pins the sentinel classification of every
// guarded engine failure so the REST layer can rely on errors.Is instead
// of message substrings. Sequenced on purpose: later steps depend on the
// volumes/snapshots created (and the dependents they leave behind) by
// earlier ones.
func TestEngineSentinelErrors(t *testing.T) {
	root := t.TempDir()
	e := NewEngine(filepath.Join(root, "cow"))

	// invalid names / sizes
	if _, err := e.CreateVolume("v", 1<<20); err != nil {
		t.Fatalf("create v: %v", err)
	}
	if _, err := e.CreateVolume("v", 1<<20); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate create: got %v, want ErrExists", err)
	}
	if _, err := e.CreateVolume("snap-x", 1<<20); !errors.Is(err, ErrInvalid) {
		t.Errorf("snap- reserved prefix: got %v, want ErrInvalid", err)
	}
	if _, err := e.CreateVolume("v2", 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero size: got %v, want ErrInvalid", err)
	}
	if _, err := e.CreateVolume("bad/name", 1<<20); !errors.Is(err, ErrInvalid) {
		t.Errorf("traversing name: got %v, want ErrInvalid", err)
	}

	// not found
	if err := e.DeleteVolume("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing volume: got %v, want ErrNotFound", err)
	}
	if _, err := e.CreateSnapshot("missing", "s1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("snapshot missing source: got %v, want ErrNotFound", err)
	}
	if err := e.DeleteSnapshot("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing snapshot: got %v, want ErrNotFound", err)
	}
	if _, err := e.CloneVolume("missing", "c0"); !errors.Is(err, ErrNotFound) {
		t.Errorf("clone missing source: got %v, want ErrNotFound", err)
	}
	if _, err := e.GetVolumeInfo("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("info missing volume: got %v, want ErrNotFound", err)
	}
	if err := e.RollbackVolume("missing", "s1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rollback missing volume: got %v, want ErrNotFound", err)
	}

	// exists
	if _, err := e.CreateSnapshot("v", "s1"); err != nil {
		t.Fatalf("create snapshot s1: %v", err)
	}
	if _, err := e.CreateSnapshot("v", "s1"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate snapshot: got %v, want ErrExists", err)
	}

	// clone + dependents veto the guarded operations
	if _, err := e.CloneVolume("v", "c1"); err != nil {
		t.Fatalf("clone c1: %v", err)
	}
	if _, err := e.CloneVolume("v", "c1"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate clone target: got %v, want ErrExists", err)
	}
	if _, err := e.CloneVolume("v", "snap-c"); !errors.Is(err, ErrInvalid) {
		t.Errorf("clone to snap- target: got %v, want ErrInvalid", err)
	}
	if err := e.DeleteVolume("v"); !errors.Is(err, ErrReferenced) {
		t.Errorf("delete referenced volume: got %v, want ErrReferenced", err)
	}
	if err := e.RollbackVolume("v", "s1"); !errors.Is(err, ErrBackedBy) {
		t.Errorf("rollback with dependent: got %v, want ErrBackedBy", err)
	}
	// snap-s1's only siblings branch from v, not from s1 — s1 must delete.
	if err := e.DeleteSnapshot("s1"); err != nil {
		t.Errorf("delete unreferenced snapshot s1: %v", err)
	}
	// With s1 gone, rollback now fails on the missing snapshot.
	if err := e.RollbackVolume("v", "s1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rollback missing snapshot: got %v, want ErrNotFound", err)
	}
}
