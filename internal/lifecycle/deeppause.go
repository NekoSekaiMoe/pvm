package lifecycle

// deeppause.go — zero-memory pause: CRIU checkpoint + process kill.
//
// The normal autopause reclaims only CPU (cgroup freeze): the UML process
// — and its whole guest — stays resident. A DEEP pause checkpoints the
// process tree to disk (criu dump, leave-running=false stops it), marks
// the task Suspended with pause_mode=deep, and only then kills the
// process: host memory drops to zero while the task stays resumable.
// DeepResume revives the exact execution state (open FDs, memory,
// processes) with criu restore.
//
// Composition with the launcher: the controller's WaitExit normally
// records a terminal status when the process dies; the Suspended+deep
// state makes it skip that (see container.WaitExit's deep-pause guard), so
// the paused task survives until DeepResume or an explicit delete.
//
// Degradation is explicit: no criu binary (or a dump failure) fails the
// DeepPause call — the caller can fall back to the shallow freeze.

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"uml-container/internal/snapshot"
	"uml-container/internal/state"
)

// DeepPause checkpoints taskID's process and kills it. The memory images
// land under <containerDir>/deeppause/criu and are recorded in the state
// metadata (pause_mode=deep, pause_memory=<dir>).
func (m *Manager) DeepPause(taskID string) error {
	st, err := state.LoadState(taskID)
	if err != nil {
		return fmt.Errorf("lifecycle: deep pause %s: %w", taskID, err)
	}
	if st.Status != state.StatusRunning {
		return fmt.Errorf("lifecycle: deep pause requires Running, task is %s", st.Status)
	}
	if st.PID <= 0 {
		return fmt.Errorf("lifecycle: deep pause %s: no live PID recorded", taskID)
	}
	if snapshot.CRIUBin() == "" {
		return snapshot.ErrCRIUUnavailable
	}
	// PID identity: the recorded pid must still name the ORIGINAL process.
	// A recycled pid would make criu dump (and the SIGKILL below) hit an
	// innocent victim; refuse before anything touches the process tree.
	if !state.PIDIdentityOK(st) {
		return fmt.Errorf("lifecycle: deep pause %s: pid %d no longer names the original "+
			"process (recycled or gone)", taskID, st.PID)
	}
	// Consistency freeze first (same barrier as event snapshots): the dump
	// must describe a quiet process tree.
	if err := m.cg.Freeze(taskID); err != nil && !isNotExist(err) {
		return fmt.Errorf("lifecycle: deep pause freeze %s: %w", taskID, err)
	}

	dir, err := state.ContainerDir(taskID)
	if err != nil {
		// The cgroup is already frozen: thaw on the way out or the task
		// stays Running-but-frozen with no recovery path.
		m.thawBestEffort(taskID)
		return fmt.Errorf("lifecycle: deep pause %s: %w", taskID, err)
	}
	memDir := filepath.Join(dir, "deeppause", "criu")
	if err := snapshot.DumpMemory(st.PID, memDir, false); err != nil {
		m.thawBestEffort(taskID)
		return fmt.Errorf("lifecycle: deep pause dump %s: %w", taskID, err)
	}

	// Persist Suspended BEFORE the kill so WaitExit's guard sees the deep
	// mode and does not record a terminal status for the intentional death.
	if st.Metadata == nil {
		st.Metadata = map[string]string{}
	}
	st.Metadata["pause_mode"] = "deep"
	st.Metadata["pause_memory"] = memDir
	if err := st.Transition(state.StatusSuspended, state.ActorSystem,
		"deep pause: memory checkpointed, process killed"); err != nil {
		m.thawBestEffort(taskID)
		return fmt.Errorf("lifecycle: deep pause %s: %w", taskID, err)
	}
	if err := state.SaveState(taskID, st); err != nil {
		m.thawBestEffort(taskID)
		return fmt.Errorf("lifecycle: deep pause %s: %w", taskID, err)
	}

	// Now the memory can actually go away. A non-ESRCH kill failure must
	// not silently return success with a live process behind a
	// Suspended+deep record: retry once, then roll the state back
	// (metadata cleared, Running again, persisted) BEFORE thawing — if the
	// rollback itself fails the cgroup stays FROZEN so the process can
	// never run against stale deep-pause bookkeeping (and DeepResume no
	// longer sees pause_mode=deep, so it cannot "restore" onto a live tree).
	if err := syscall.Kill(st.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		if retry := syscall.Kill(st.PID, syscall.SIGKILL); retry != nil && retry != syscall.ESRCH {
			delete(st.Metadata, "pause_mode")
			delete(st.Metadata, "pause_memory")
			rolledBack := false
			if st.Transition(state.StatusResuming, state.ActorSystem, "deep pause kill failed: rolling back") == nil {
				if st.Transition(state.StatusRunning, state.ActorSystem, "deep pause kill failed: rolled back") == nil {
					rolledBack = state.SaveState(taskID, st) == nil
				}
			}
			if !rolledBack {
				return fmt.Errorf(
					"lifecycle: deep pause %s: kill %d failed and the state rollback "+
						"failed; task left FROZEN as Suspended+deep (recover manually): %w",
					taskID, st.PID, err)
			}
			m.thawBestEffort(taskID)
			return fmt.Errorf(
				"lifecycle: deep pause %s: kill %d failed after checkpoint; "+
					"state restored to Running and cgroup thawed: %w",
				taskID, st.PID, err)
		}
	}
	m.Disarm(taskID)
	return nil
}

// DeepResume revives a deep-paused task from its memory images.
func (m *Manager) DeepResume(taskID string) error {
	st, err := state.LoadState(taskID)
	if err != nil {
		return fmt.Errorf("lifecycle: deep resume %s: %w", taskID, err)
	}
	if st.Status != state.StatusSuspended || st.Metadata["pause_mode"] != "deep" {
		return fmt.Errorf("lifecycle: deep resume %s: task is not deep-paused (status %s)",
			taskID, st.Status)
	}
	memDir := st.Metadata["pause_memory"]
	if memDir == "" {
		return fmt.Errorf("lifecycle: deep resume %s: no pause_memory recorded", taskID)
	}
	if _, err := os.Stat(memDir); err != nil {
		return fmt.Errorf("lifecycle: deep resume %s: memory images missing: %w", taskID, err)
	}
	if err := st.Transition(state.StatusResuming, state.ActorSystem, "deep resume"); err != nil {
		return fmt.Errorf("lifecycle: deep resume %s: %w", taskID, err)
	}
	restoredPID, err := snapshot.RestoreMemory(memDir)
	if err != nil {
		// Back to Suspended: the images (and the deep mode) survive for a
		// retry or an operator's fresh-boot rollback.
		_ = st.Transition(state.StatusSuspended, state.ActorSystem, "deep resume failed: "+err.Error())
		_ = state.SaveState(taskID, st)
		return fmt.Errorf("lifecycle: deep resume %s: %w", taskID, err)
	}
	delete(st.Metadata, "pause_mode")
	delete(st.Metadata, "pause_memory")
	// Stamp the ACTUAL restored root pid (criu --pidfile) — not the stale
	// pre-checkpoint one — so a second DeepPause passes the recycled-pid
	// guard (the historical code zeroed the PID, which made every later
	// deep pause fail with "no live PID recorded"). The running state is
	// persisted only after the stamp succeeded.
	state.StampPID(st, restoredPID)
	if err := st.Transition(state.StatusRunning, state.ActorSystem,
		"deep resume complete"); err != nil {
		return fmt.Errorf("lifecycle: deep resume %s: %w", taskID, err)
	}
	return state.SaveState(taskID, st)
}

// IsDeepPaused reports whether the task's persisted state is a deep pause
// (used by the resume endpoints to pick DeepResume vs thaw).
func IsDeepPaused(taskID string) bool {
	st, err := state.LoadState(taskID)
	if err != nil || st == nil {
		return false
	}
	return st.Status == state.StatusSuspended && st.Metadata["pause_mode"] == "deep"
}

// SetDeepPause arms per-task deep mode for the AUTOPAUSE path: when the
// idle timer fires, the task is checkpointed and killed instead of merely
// frozen. Memory is reclaimed at the cost of a criu-restore resume.
func (m *Manager) SetDeepPause(taskID string, deep bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deepTasks == nil {
		m.deepTasks = map[string]bool{}
	}
	if deep {
		m.deepTasks[taskID] = true
	} else {
		delete(m.deepTasks, taskID)
	}
}

func (m *Manager) deepPauseWanted(taskID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deepTasks[taskID]
}
