package snapshot

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"uml-container/internal/state"
)

func TestClone(t *testing.T) {
	tmpDir := t.TempDir()
	orig := state.RootDir
	state.RootDir = tmpDir
	defer func() { state.RootDir = orig }()

	srcID := "source-task"
	cDir, err := state.ContainerDir(srcID)
	if err != nil {
		t.Fatalf("ContainerDir: %v", err)
	}
	if err := os.MkdirAll(cDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cDir, "rootfs.img"), []byte("mock-rootfs-data"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	st := &state.ContainerState{
		ID:        srcID,
		Name:      srcID,
		Tenant:    "engineering",
		Status:    state.StatusRunning,
		PID:       12345,
		StartedAt: time.Now().UTC(),
	}
	if err := state.SaveState(srcID, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	t.Run("HappyPathAndIsolation", func(t *testing.T) {
		dstID := "cloned-task"
		if err := Clone(srcID, dstID); err != nil {
			t.Fatalf("Clone: %v", err)
		}

		clonedState, err := state.LoadState(dstID)
		if err != nil {
			t.Fatalf("LoadState cloned: %v", err)
		}
		if clonedState.ID != dstID {
			t.Errorf("clonedState.ID = %q, want %q", clonedState.ID, dstID)
		}
		if clonedState.Tenant != "engineering" {
			t.Errorf("clonedState.Tenant = %q, want %q", clonedState.Tenant, "engineering")
		}
		if clonedState.Status != state.StatusReady {
			t.Errorf("clonedState.Status = %q, want %q", clonedState.Status, state.StatusReady)
		}
		if clonedState.PID != 0 {
			t.Errorf("clonedState.PID = %d, want 0", clonedState.PID)
		}

		// The clone must produce disk artifacts, not just state: the source
		// only has rootfs.img, so Clone either branches an overlay.qcow2 from
		// it (CreateOverlay) or falls back to copying rootfs.img — assert at
		// least one landed in the cloned task's directory.
		dstDir, err := state.ContainerDir(dstID)
		if err != nil {
			t.Fatalf("ContainerDir cloned: %v", err)
		}
		if _, oerr := os.Stat(filepath.Join(dstDir, "overlay.qcow2")); oerr != nil {
			if _, rerr := os.Stat(filepath.Join(dstDir, "rootfs.img")); rerr != nil {
				t.Errorf("cloned dir has neither overlay.qcow2 nor rootfs.img (overlay: %v, rootfs: %v)", oerr, rerr)
			}
		}
	})

	t.Run("DuplicateTargetFails", func(t *testing.T) {
		if err := Clone(srcID, "cloned-task"); err == nil {
			t.Fatal("expected error cloning to existing ID")
		}
	})

	t.Run("NonExistentSourceFails", func(t *testing.T) {
		if err := Clone("does-not-exist", "new-id"); err == nil {
			t.Fatal("expected error cloning from non-existent ID")
		}
	})
}

func TestRollback(t *testing.T) {
	tmpDir := t.TempDir()
	orig := state.RootDir
	state.RootDir = tmpDir
	defer func() { state.RootDir = orig }()

	taskID := "task-rollback-test"
	cDir, err := state.ContainerDir(taskID)
	if err != nil {
		t.Fatalf("ContainerDir: %v", err)
	}
	if err := os.MkdirAll(cDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	st := &state.ContainerState{
		ID:        taskID,
		Name:      taskID,
		Status:    state.StatusReady,
		StartedAt: time.Now().UTC(),
	}
	if err := state.SaveState(taskID, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// 1. Create snapshot in Ready state
	snap, err := CreateEventSnapshot(taskID, "init_point", "hash-init", nil)
	if err != nil {
		t.Fatalf("CreateEventSnapshot: %v", err)
	}

	t.Run("HappyPathRestore", func(t *testing.T) {
		// Change state to Failed
		st.Status = state.StatusFailed
		if err := state.SaveState(taskID, st); err != nil {
			t.Fatalf("SaveState failed: %v", err)
		}

		// Rollback to snap
		if err := Rollback(taskID, snap.ID); err != nil {
			t.Fatalf("Rollback: %v", err)
		}

		// Verify state restored to Ready
		restored, err := state.LoadState(taskID)
		if err != nil {
			t.Fatalf("LoadState restored: %v", err)
		}
		if restored.Status != state.StatusReady {
			t.Errorf("restored.Status = %q, want %q", restored.Status, state.StatusReady)
		}
		if len(restored.Transitions) == 0 {
			t.Fatal("expected transition log to contain rollback record")
		}
		lastTr := restored.Transitions[len(restored.Transitions)-1]
		if lastTr.To != state.StatusReady || lastTr.Actor != state.ActorHuman {
			t.Errorf("unexpected last transition: %+v", lastTr)
		}
	})

	t.Run("NonExistentSnapshotFails", func(t *testing.T) {
		if err := Rollback(taskID, "snap-non-existent"); err == nil {
			t.Fatal("expected error on non-existent snapshot rollback")
		}
	})
}
