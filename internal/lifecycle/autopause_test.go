package lifecycle

import (
	"testing"
	"time"

	"uml-container/internal/state"
)

// TestAutopause_StaleCallbackCannotPause is the regression test for the
// timer race: a callback that fired just before a Reset (or after a Disarm)
// must not pause the task, and pause() must not delete a newer schedule.
// It drives pause() directly with a stale generation instead of racing real
// timers, so the result is deterministic.
func TestAutopause_StaleCallbackCannotPause(t *testing.T) {
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())

	id := "stale-cb"
	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusRunning}
	if err := state.SaveState(id, st); err != nil {
		t.Fatalf("save: %v", err)
	}

	m := New(nil)
	m.Arm(id, time.Hour)   // generation 1
	m.Reset(id, time.Hour) // generation 2 supersedes it

	// Simulate the generation-1 callback that fired right before the Reset
	// completed: it must be a no-op.
	m.pause(id, 1)
	loaded, err := state.LoadState(id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Status != state.StatusRunning {
		t.Fatalf("stale callback paused the task: status=%q", loaded.Status)
	}

	// The live (generation-2) schedule must still work: an authorized pause
	// transitions, and afterwards Disarm leaves nothing behind.
	m.pause(id, 2)
	loaded2, _ := state.LoadState(id)
	if loaded2.Status != state.StatusSuspended {
		t.Fatalf("current-generation callback failed to pause: status=%q", loaded2.Status)
	}
	m.Disarm(id)

	// After Disarm there is no valid generation left: even the current one
	// must be a no-op (a callback racing Disarm).
	m.pause(id, 2)
	loaded3, _ := state.LoadState(id)
	if loaded3.Status != state.StatusSuspended {
		t.Fatalf("unexpected state change after disarm: %q", loaded3.Status)
	}
}

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
	m.Reset(id, 80*time.Millisecond)  // bump
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
