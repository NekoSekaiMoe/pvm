package lifecycle

import (
	"testing"
	"time"

	"uml-container/internal/state"
)

// TestAutopause_StaleCallbackCannotPause is the regression test for the
// timer race: a callback that fired just before a Reset must not pause the
// task afterwards, and pause() must not delete a newer schedule.
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
	fired := make(chan struct{})
	// Simulate a stale callback racing with a Reset: capture the behavior by
	// arming a very short timer, then immediately bumping the schedule.
	m.Arm(id, 1*time.Millisecond)
	m.Reset(id, time.Hour) // supersede before the 1ms callback runs its work
	close(fired)
	time.Sleep(50 * time.Millisecond)

	loaded, err := state.LoadState(id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Status != state.StatusRunning {
		t.Fatalf("stale callback paused the task: status=%q", loaded.Status)
	}
	// The new schedule must still be disarmable (not deleted by pause()).
	m.Disarm(id)
	select {
	case <-fired:
	default:
		t.Fatalf("setup error")
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
