package lifecycle

// balloon.go — memory ballooning for paused tasks.
//
// A shallow pause reclaims only CPU (cgroup freeze): the process tree and its
// whole resident set stay in RAM. To let the host reclaim the paused task's
// clean page cache — without killing the process, as a deep pause would — we
// lower the task's cgroup memory.max to its current usage. The frozen task
// performs no allocations, so nothing trips the new limit; on resume the
// original limit is restored BEFORE the thaw so the revived process is not
// squeezed into an OOM.
//
// Everything here is best effort: a missing cgroup (task exited, tests) or an
// unreadable memory file simply skips the balloon. The prior limit is recorded
// in the persisted state metadata so a resume (including one after a server
// restart) can restore it.

import (
	"strconv"

	"uml-container/internal/cgroup"
	"uml-container/internal/state"
)

// pauseMemoryMaxKey is the state-metadata key holding the memory.max value a
// paused task had before BalloonPause lowered it. Its presence marks a task
// as ballooned; RestorePauseBalloon removes it.
const pauseMemoryMaxKey = "pause_memory_max"

// BalloonPause lowers a Suspended task's cgroup memory.max to current usage,
// without raising an existing lower limit, and persists the prior limit in
// state metadata. It is a no-op if the task is not Suspended, is already
// ballooned, or reports nonpositive usage. State and cgroup read/write errors
// are returned, including missing cgroups. If saving the marker fails, it
// attempts to restore the prior limit and returns the save error.
func (m *Manager) BalloonPause(taskID string) error {
	st, err := state.LoadState(taskID)
	if err != nil {
		return err
	}
	if st.Status != state.StatusSuspended {
		return nil
	}
	if st.Metadata == nil {
		st.Metadata = map[string]string{}
	}
	if _, done := st.Metadata[pauseMemoryMaxKey]; done {
		return nil // already ballooned
	}
	orig, err := m.cg.MemoryMax(taskID)
	if err != nil {
		return err // cgroup gone: nothing to balloon
	}
	cur, err := m.cg.MemoryCurrent(taskID)
	if err != nil {
		return err
	}
	if cur <= 0 {
		return nil
	}
	// Target the current usage; never RAISE a task's limit to do so (a task
	// whose limit is already below its current usage — e.g. a limit being
	// enforced — keeps that limit).
	target := cur
	if orig != cgroup.MemoryUnlimited && orig < target {
		target = orig
	}
	if err := m.cg.SetMemoryMax(taskID, target); err != nil {
		return err
	}
	st.Metadata[pauseMemoryMaxKey] = strconv.FormatInt(orig, 10)
	if err := saveState(taskID, st); err != nil {
		// The limit was lowered but the bookkeeping could not be persisted:
		// undo the limit so the runtime matches the on-disk state (no balloon
		// recorded) and the caller can retry.
		_ = m.cg.SetMemoryMax(taskID, orig)
		return err
	}
	return nil
}

// RestorePauseBalloon attempts to restore the limit recorded by BalloonPause
// and clears the metadata marker in st; the caller must persist st. It is a
// no-op for nil state or a missing marker. Malformed markers and cgroup write
// errors are ignored, and the marker is cleared even if restoration fails.
func (m *Manager) RestorePauseBalloon(taskID string, st *state.ContainerState) {
	if st == nil || st.Metadata == nil {
		return
	}
	raw, ok := st.Metadata[pauseMemoryMaxKey]
	if !ok {
		return
	}
	delete(st.Metadata, pauseMemoryMaxKey)
	orig, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return
	}
	// Restoring the limit is a safety requirement (the thawed process must
	// not inherit the balloon); a missing cgroup is fine and other errors
	// have no remedy here.
	_ = m.cg.SetMemoryMax(taskID, orig)
}
