package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"uml-container/internal/state"
)

// setupRunning saves a Running task and points the cgroup root at a regular
// FILE, so cgroup.Manager.Freeze fails with ENOTDIR — a genuine (non-ENOENT)
// freeze failure that drives pause's retry path deterministically.
func setupRunning(t *testing.T, id string) *Manager {
	t.Helper()
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })

	cgRoot := filepath.Join(t.TempDir(), "cgroot-is-a-file")
	if err := os.WriteFile(cgRoot, []byte("x"), 0644); err != nil {
		t.Fatalf("seed cgroup root file: %v", err)
	}
	t.Setenv("PVM_CGROUP_ROOT", cgRoot)

	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusRunning}
	if err := state.SaveState(id, st); err != nil {
		t.Fatalf("save: %v", err)
	}
	return New(nil)
}

// TestAutopause_FreezeFailureRetriesWithoutPausing: a genuine freeze failure
// must leave the task Running and schedule a retry instead of going silent.
func TestAutopause_FreezeFailureRetriesWithoutPausing(t *testing.T) {
	id := "freeze-fail"
	m := setupRunning(t, id)

	m.Arm(id, time.Hour) // gen 1
	gen1 := m.gens[id]
	m.pause(id, gen1)

	if loaded, _ := state.LoadState(id); loaded.Status != state.StatusRunning {
		t.Fatalf("failed freeze must not pause the task: %q", loaded.Status)
	}
	if m.timers[id] == nil {
		t.Fatalf("failed freeze must schedule a retry timer")
	}
	if m.gens[id] == gen1 {
		t.Fatalf("retry must install a fresh generation")
	}
}

// TestAutopause_RetryDoesNotClobberReset is the regression test for the
// retry race: a Reset (or Disarm) that lands while a pause is failing to
// freeze must win — the stale pause's retry may neither replace the fresh
// idle window nor resurrect a disarmed task.
func TestAutopause_RetryDoesNotClobberReset(t *testing.T) {
	id := "retry-vs-reset"
	m := setupRunning(t, id)

	m.Arm(id, time.Hour)
	staleEpoch := m.epochs[id]

	// Simulate the pause having started (captured staleEpoch) and a Reset
	// landing mid-freeze: the epoch bumps and a fresh idle window is armed.
	m.Reset(id, 5*time.Minute)
	freshGen := m.gens[id]

	// The stale pause now reaches its retry decision — it must be a no-op.
	m.rearmRetry(id, staleEpoch)
	if m.gens[id] != freshGen {
		t.Fatalf("stale retry clobbered the fresh schedule: gen=%d want=%d", m.gens[id], freshGen)
	}
	if m.timers[id] == nil {
		t.Fatalf("stale retry must leave the fresh timer armed")
	}

	// Same for Disarm: after an explicit disarm the retry must not
	// resurrect the schedule.
	m.Disarm(id)
	m.rearmRetry(id, staleEpoch)
	if m.timers[id] != nil {
		t.Fatalf("stale retry resurrected a disarmed task")
	}
	if m.gens[id] != 0 {
		t.Fatalf("disarmed task must have no live generation, got %d", m.gens[id])
	}

	// End to end: with an unchanged epoch the retry still arms (the happy
	// retry path from TestAutopause_FreezeFailureRetriesWithoutPausing),
	// observable through the epoch guard itself.
	m.Arm(id, time.Hour)
	m.rearmRetry(id, m.epochs[id])
	if m.timers[id] == nil {
		t.Fatalf("unchanged epoch must allow the retry")
	}
}
