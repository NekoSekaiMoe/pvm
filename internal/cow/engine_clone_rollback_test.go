package cow

import (
	"path/filepath"
	"testing"
)

func TestEngine_CloneAndRollbackVolume(t *testing.T) {
	root := t.TempDir()
	e := NewEngine(root)

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

	// 3. Clone volume from snapshot
	clonedPath, err := e.CloneVolume("snap-1", "cloned-vol")
	if err != nil {
		t.Fatalf("CloneVolume from snap: %v", err)
	}
	if filepath.Dir(clonedPath) != root {
		t.Fatalf("unexpected dir: %s", clonedPath)
	}

	// 4. Clone volume from another volume
	cloned2, err := e.CloneVolume("base-vol", "cloned-vol-2")
	if err != nil {
		t.Fatalf("CloneVolume from vol: %v", err)
	}
	if filepath.Dir(cloned2) != root {
		t.Fatalf("unexpected dir: %s", cloned2)
	}

	// 5. Duplicate clone error
	if _, err := e.CloneVolume("base-vol", "cloned-vol"); err == nil {
		t.Fatal("expected error cloning to existing volume name")
	}

	// 6. Rollback base volume to snapshot snap-1
	if err := e.RollbackVolume("base-vol", "snap-1"); err != nil {
		t.Fatalf("RollbackVolume: %v", err)
	}

	// 7. Rollback non-existent volume / snapshot
	if err := e.RollbackVolume("non-existent-vol", "snap-1"); err == nil {
		t.Fatal("expected error rolling back non-existent volume")
	}
	if err := e.RollbackVolume("base-vol", "non-existent-snap"); err == nil {
		t.Fatal("expected error rolling back to non-existent snapshot")
	}
}
