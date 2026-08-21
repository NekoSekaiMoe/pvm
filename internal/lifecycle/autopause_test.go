package lifecycle

import (
	"os"
	"path/filepath"
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

	// Poll instead of sleeping a fixed 80ms: on a loaded CI runner (bazel
	// test //... runs every test binary in parallel) the pause callback can
	// be descheduled for tens of milliseconds after the timer fires, so a
	// fixed sleep sees a stale "running". Timers never fire early, so
	// waiting for the transition cannot false-pass; it can only fail if the
	// callback never runs at all.
	if !waitForStatus(t, id, state.StatusSuspended, 2*time.Second) {
		t.Fatalf("status after autopause = %q, want suspended", mustStatus(t, id))
	}

	if err := m.Resume(id); err != nil {
		t.Fatalf("resume: %v", err)
	}
	loaded2, _ := state.LoadState(id)
	if loaded2.Status != state.StatusRunning {
		t.Fatalf("status after resume = %q, want running", loaded2.Status)
	}
}

// TestAutopause_ResumeRearmsIdleTimer is the regression test for the resume
// path: a task with a positive idle_timeout that gets suspended and resumed
// must fall back to Suspended when it goes idle AGAIN — before the fix,
// Resume never re-armed the idle timer, so one suspend/resume cycle
// permanently exempted the task from autopause.
func TestAutopause_ResumeRearmsIdleTimer(t *testing.T) {
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())

	id := "resume-rearm"
	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusSuspended, IdleTimeout: "30ms"}
	if err := state.SaveState(id, st); err != nil {
		t.Fatalf("save: %v", err)
	}

	m := New(nil)
	if err := m.Resume(id); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if loaded, _ := state.LoadState(id); loaded.Status != state.StatusRunning {
		t.Fatalf("status after resume = %q, want running", mustStatus(t, id))
	}
	// The re-armed idle timer must fire again: same polling rationale as
	// TestAutopause_FiresAndResume (timers never fire early, so waiting for
	// the second suspension cannot false-pass).
	if !waitForStatus(t, id, state.StatusSuspended, 2*time.Second) {
		t.Fatalf("task did not auto-pause again after resume: status=%q", mustStatus(t, id))
	}
}

// TestAutopause_ResumeWithoutTimeoutStaysUnarmed pins the other half of the
// contract: a task with no (or non-positive) idle_timeout must not gain an
// idle timer from Resume — invalid/unset timeouts keep the pre-existing
// "never armed" behavior.
func TestAutopause_ResumeWithoutTimeoutStaysUnarmed(t *testing.T) {
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())

	id := "resume-notimeout"
	for _, idle := range []string{"", "not-a-duration", "0s", "-5s"} {
		st := &state.ContainerState{ID: id, Name: id, Status: state.StatusSuspended, IdleTimeout: idle}
		if err := state.SaveState(id, st); err != nil {
			t.Fatalf("save: %v", err)
		}
		m := New(nil)
		if err := m.Resume(id); err != nil {
			t.Fatalf("resume (idle=%q): %v", idle, err)
		}
		m.mu.Lock()
		_, armed := m.timers[id]
		m.mu.Unlock()
		if armed {
			t.Fatalf("resume with idle_timeout=%q must not arm a timer", idle)
		}
		// back to Suspended for the next iteration
		loaded, err := state.LoadState(id)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		loaded.Status = state.StatusSuspended
		if err := state.SaveState(id, loaded); err != nil {
			t.Fatalf("re-save: %v", err)
		}
	}
}

// waitForStatus polls until the task reaches the wanted status or the
// deadline passes; it returns whether the status was reached.
func waitForStatus(t *testing.T, id string, want state.Status, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if st, err := state.LoadState(id); err == nil && st.Status == want {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
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
	// The original schedule (200ms) is superseded immediately (Reset is a
	// full re-Arm, so no delay is needed to be "inside" the window — the
	// original deadline just has to be far enough out that no realistic
	// scheduler stall between the two adjacent statements lets it fire).
	// The reset deadline must land well AFTER the observation window below.
	const (
		origDeadline  = 200 * time.Millisecond
		resetDeadline = 1 * time.Second
		window        = 500 * time.Millisecond // > origDeadline, < resetDeadline
	)
	m.Arm(id, origDeadline)
	m.Reset(id, resetDeadline)

	// Observation window: cross the ORIGINAL deadline and assert the task
	// never gets suspended by it. Polling bounded by wall clock is sound
	// because timers never fire early: under correct behavior every
	// in-window observation sees "running"; a scheduler stall only skips
	// polls (the loop guard drops out-of-window checks), never fabricates a
	// suspension. Only a superseded-but-still-live schedule fails here.
	windowEnd := time.Now().Add(window)
	for time.Now().Before(windowEnd) {
		if s := mustStatus(t, id); s == state.StatusSuspended {
			t.Fatalf("autopause fired despite reset (deadline was bumped to %v)", resetDeadline)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Now wait for the reset deadline to fire; polling instead of a fixed
	// sleep so a slow runner still observes it. This also fails if Reset
	// dropped the schedule entirely (no suspension would ever arrive).
	if !waitForStatus(t, id, state.StatusSuspended, 4*time.Second) {
		t.Fatalf("expected suspended after bumped deadline, got %q", mustStatus(t, id))
	}
}

func mustStatus(t *testing.T, id string) state.Status {
	t.Helper()
	st, err := state.LoadState(id)
	if err != nil {
		t.Fatalf("load %s: %v", id, err)
	}
	return st.Status
}

// TestAutopause_EpochChangeAfterFreezeCannotCommit is the regression test
// for the commit window: a pause whose generation was still current when it
// started, but whose schedule was replaced (Reset) or cancelled (Disarm)
// while the freeze was running, must not commit Suspended. It drives
// commitPause directly with the captured epoch, so no real racing is
// involved.
func TestAutopause_EpochChangeAfterFreezeCannotCommit(t *testing.T) {
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())

	id := "epoch-commit"
	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusRunning}
	if err := state.SaveState(id, st); err != nil {
		t.Fatalf("save: %v", err)
	}

	m := New(nil)
	m.Arm(id, time.Hour) // epoch 1, generation 1
	m.Disarm(id)         // epoch bumped to 2 while the pause was in flight

	// The in-flight pause still holds epoch 1: committing on it must be
	// rejected, and no retry may be armed for the disarmed task.
	m.commitPause(id, 1, st)

	loaded, err := state.LoadState(id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Status != state.StatusRunning {
		t.Fatalf("stale-epoch pause committed: status=%q", loaded.Status)
	}
	m.mu.Lock()
	_, rearmed := m.timers[id]
	m.mu.Unlock()
	if rearmed {
		t.Fatalf("retry armed for a disarmed task")
	}
}

// TestAutopause_SaveFailureThawsAndRearms verifies the unwind path: when
// the FSM transition succeeds but persisting Suspended fails, the task must
// not be left frozen with no timer armed (a state that never self-heals) —
// a retry is scheduled instead.
func TestAutopause_SaveFailureThawsAndRearms(t *testing.T) {
	root := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = root
	t.Cleanup(func() { state.RootDir = origRoot })
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())

	// Pre-create <root>/<id> as a regular file so SaveState's MkdirAll
	// fails deterministically (LoadState is not on this path).
	id := "save-fail"
	if err := os.WriteFile(filepath.Join(root, id), []byte("x"), 0644); err != nil {
		t.Fatalf("block state dir: %v", err)
	}

	m := New(nil)
	m.Arm(id, time.Hour) // epoch 1
	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusRunning}
	m.commitPause(id, 1, st)

	m.mu.Lock()
	_, rearmed := m.timers[id]
	m.mu.Unlock()
	if !rearmed {
		t.Fatalf("no retry armed after SaveState failure")
	}
	m.Disarm(id) // stop the retry timer before the test ends
}
