package cow

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestEngine(t *testing.T) (*Qcow2Engine, string) {
	t.Helper()
	root := t.TempDir()
	e := NewEngine(root)
	return e, root
}

func TestEngine_CloneAndRollbackVolume(t *testing.T) {
	e, root := setupTestEngine(t)

	// 1. Create base volume
	volPath, err := e.CreateVolume("base-vol", 1<<20)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	if filepath.Dir(volPath) != root {
		t.Fatalf("unexpected dir: %s", volPath)
	}

	// 2. Create snapshot of base volume
	snapPath, err := e.CreateSnapshot("base-vol", "snap-1")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if filepath.Dir(snapPath) != root {
		t.Fatalf("unexpected dir: %s", snapPath)
	}

	t.Run("CloneFromSnapshot", func(t *testing.T) {
		clonedPath, err := e.CloneVolume("snap-1", "cloned-vol")
		if err != nil {
			t.Fatalf("CloneVolume from snap: %v", err)
		}
		if filepath.Dir(clonedPath) != root {
			t.Fatalf("unexpected dir: %s", clonedPath)
		}
	})

	t.Run("CloneFromVolume", func(t *testing.T) {
		cloned2, err := e.CloneVolume("base-vol", "cloned-vol-2")
		if err != nil {
			t.Fatalf("CloneVolume from vol: %v", err)
		}
		if filepath.Dir(cloned2) != root {
			t.Fatalf("unexpected dir: %s", cloned2)
		}
	})

	t.Run("CloneDuplicateTarget", func(t *testing.T) {
		if _, err := e.CloneVolume("base-vol", "cloned-vol"); err == nil {
			t.Fatal("expected error cloning to existing volume name")
		}
	})

	t.Run("CloneNonExistentSource", func(t *testing.T) {
		if _, err := e.CloneVolume("non-existent-src", "new-vol"); err == nil {
			t.Fatal("expected error cloning from non-existent source")
		}
	})

	t.Run("DeleteReferencedSnapshotAndVolumeRejected", func(t *testing.T) {
		// snap-1 is referenced by cloned-vol; base-vol is referenced by snap-1 and cloned-vol-2
		if err := e.DeleteSnapshot("snap-1"); err == nil {
			t.Fatal("expected error deleting referenced snapshot")
		}
		if err := e.DeleteVolume("base-vol"); err == nil {
			t.Fatal("expected error deleting referenced volume")
		}
	})

	t.Run("RollbackVolumeWithDependentRejected", func(t *testing.T) {
		// cloned-vol-2 is still backed by base-vol: replacing base-vol in
		// place would silently swap the content under that live clone.
		if err := e.RollbackVolume("base-vol", "snap-1"); err == nil {
			t.Fatal("expected rollback to be rejected while a dependent still references the volume")
		}
	})

	t.Run("RollbackVolume", func(t *testing.T) {
		// Remove the dependents first: cloned-vol is backed by snap-1 and
		// cloned-vol-2 by base-vol. The rollback TARGET snapshot snap-1 is
		// the only remaining reference to base-vol and must not block it.
		if err := e.DeleteVolume("cloned-vol"); err != nil {
			t.Fatalf("DeleteVolume cloned-vol: %v", err)
		}
		if err := e.DeleteVolume("cloned-vol-2"); err != nil {
			t.Fatalf("DeleteVolume cloned-vol-2: %v", err)
		}
		if err := e.RollbackVolume("base-vol", "snap-1"); err != nil {
			t.Fatalf("RollbackVolume: %v", err)
		}
		// The rolled-back volume exists, is a standalone image the engine
		// can open, and the rollback temp file did not survive.
		volPath := filepath.Join(root, "base-vol.qcow2")
		if _, err := os.Stat(volPath); err != nil {
			t.Fatalf("rolled-back volume missing: %v", err)
		}
		info, err := e.GetVolumeInfo("base-vol")
		if err != nil {
			t.Fatalf("open rolled-back volume via engine: %v", err)
		}
		if info.DevicePath != volPath {
			t.Errorf("GetVolumeInfo path = %q, want %q", info.DevicePath, volPath)
		}
		if _, err := os.Stat(filepath.Join(root, ".tmp-rb-base-vol.qcow2")); !os.IsNotExist(err) {
			t.Fatalf("rollback temp file must not survive a successful rollback (stat err = %v)", err)
		}
	})

	t.Run("RollbackNonExistentVolume", func(t *testing.T) {
		if err := e.RollbackVolume("non-existent-vol", "snap-1"); err == nil {
			t.Fatal("expected error rolling back non-existent volume")
		}
	})

	t.Run("RollbackNonExistentSnapshot", func(t *testing.T) {
		if err := e.RollbackVolume("base-vol", "non-existent-snap"); err == nil {
			t.Fatal("expected error rolling back to non-existent snapshot")
		}
	})

	t.Run("DeleteUnreferencedVolumeAndSnapshot", func(t *testing.T) {
		// cloned-vol / cloned-vol-2 were already removed ahead of the
		// rollback above; snap-1's (stale) backing still names base-vol, so
		// it must go first — exactly the referenced-delete guard at work.
		if err := e.DeleteSnapshot("snap-1"); err != nil {
			t.Fatalf("DeleteSnapshot snap-1: %v", err)
		}
		if err := e.DeleteVolume("base-vol"); err != nil {
			t.Fatalf("DeleteVolume base-vol: %v", err)
		}
	})
}
