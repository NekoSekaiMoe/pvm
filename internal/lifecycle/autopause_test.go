package lifecycle

import (
	"testing"
	"time"

	"uml-container/internal/state"
)

func TestAutopause_FiresAndResume(t *testing.T) {
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })
	cgRoot := t.TempDir()
	t.Setenv("PVM_CGROUP_ROOT", cgRoot)

	id := "autopause-test"
	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusRunning}
	if err := state.SaveState(id, st); err != nil {
		t.Fatalf("save: %v", err)
	}

	m := New(nil)
	m.Arm(id, 30*time.Millisecond)
	time.Sleep(80 * time.Millisecond)

	loaded, err := state.LoadState(id)
	if err != nil {
		t.Fatalf("load after pause: %v", err)
	}
	if loaded.Status != state.StatusSuspended {
		t.Fatalf("status after autopause = %q, want suspended", loaded.Status)
	}

	if err := m.Resume(id); err != nil {
		t.Fatalf("resume: %v", err)
	}
	loaded2, _ := state.LoadState(id)
	if loaded2.Status != state.StatusRunning {
		t.Fatalf("status after resume = %q, want running", loaded2.Status)
	}
}

func TestAutopause_ResetBumpsDeadline(t *testing.T) {
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })
	cgRoot := t.TempDir()
	t.Setenv("PVM_CGROUP_ROOT", cgRoot)

	id := "reset-test"
	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusRunning}
	_ = state.SaveState(id, st)

	m := New(nil)
	m.Arm(id, 80*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	m.Reset(id, 80*time.Millisecond) // bump
	time.Sleep(40 * time.Millisecond) // would have fired at 80ms from first arm

	loaded, _ := state.LoadState(id)
	if loaded.Status == state.StatusSuspended {
		t.Fatalf("autopause fired despite reset")
	}
	// Now let it fire
	time.Sleep(60 * time.Millisecond)
	loaded2, _ := state.LoadState(id)
	if loaded2.Status != state.StatusSuspended {
		t.Fatalf("expected suspended after bumped deadline, got %q", loaded2.Status)
	}
}
