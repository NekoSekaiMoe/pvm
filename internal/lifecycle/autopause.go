// Package lifecycle provides single-host AutoPause/AutoResume,
// mirroring CubeSandbox docs/guide/lifecycle.md at UML scale.
//
// Pausing reclaims CPU via cgroup freeze (cgroup.Manager.Freeze) and
// transitions the FSM Running -> Suspended. Resuming thaws and moves
// Suspended -> Resuming -> Running. No Redis, no cross-node migration —
// the timers run in-process.
package lifecycle

import (
	"errors"
	"os"
	"sync"
	"time"

	"uml-container/internal/cgroup"
	"uml-container/internal/state"
)

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || (err != nil && os.IsNotExist(err))
}

// Manager owns per-task idle timers.
type Manager struct {
	mu      sync.Mutex
	timers  map[string]*time.Timer
	gens    map[string]uint64 // taskID -> generation of the live schedule
	epochs  map[string]uint64 // taskID -> cancel epoch; bumped by every Arm/Disarm
	nextGen uint64
	cg      *cgroup.Manager
}

// New creates a Manager. cg may be nil to use the default cgroup root.
func New(cg *cgroup.Manager) *Manager {
	if cg == nil {
		cg = cgroup.NewManager()
	}
	return &Manager{
		timers: make(map[string]*time.Timer),
		gens:   make(map[string]uint64),
		epochs: make(map[string]uint64),
		cg:     cg,
	}
}

// Arm starts (or resets) the idle countdown for taskID. When d elapses
// without a Reset/Disarm, the task is frozen and moved to Suspended.
// d <= 0 disables autopause for this task.
//
// Every Arm stamps a new generation; the scheduled callback verifies its
// generation before pausing, so a callback from a replaced (Reset) or
// cancelled (Disarm) schedule can never pause a task afterwards.
func (m *Manager) Arm(taskID string, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.armLocked(taskID, d)
}

// armLocked is Arm assuming m.mu is held. Every schedule change bumps the
// task's cancel epoch so an in-flight pause (see pause) can detect that its
// schedule was replaced and must not re-arm a retry on top of it.
func (m *Manager) armLocked(taskID string, d time.Duration) {
	m.epochs[taskID]++
	if old, ok := m.timers[taskID]; ok {
		old.Stop()
		delete(m.timers, taskID)
	}
	// Dropping the generation entry invalidates any callback that already
	// fired and is racing towards pause().
	delete(m.gens, taskID)
	if d <= 0 {
		return
	}
	m.nextGen++
	gen := m.nextGen
	m.gens[taskID] = gen
	m.timers[taskID] = time.AfterFunc(d, func() { m.pause(taskID, gen) })
}

// Reset bumps the idle deadline for taskID (call on every API activity).
func (m *Manager) Reset(taskID string, d time.Duration) {
	m.Arm(taskID, d)
}

// Disarm cancels any pending autopause for taskID (call on destroy/manual pause).
func (m *Manager) Disarm(taskID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epochs[taskID]++ // invalidate an in-flight pause's retry (see pause)
	if t, ok := m.timers[taskID]; ok {
		t.Stop()
		delete(m.timers, taskID)
	}
	// Removing the generation entry also stops an already-fired callback
	// that has not reached pause() yet.
	delete(m.gens, taskID)
}

// Resume thaws a Suspended task and drives Suspended -> Resuming -> Running.
// Returns an error if the task is not in Suspended or thaw fails.
func (m *Manager) Resume(taskID string) error {
	st, err := state.LoadState(taskID)
	if err != nil {
		return err
	}
	if st.Status != state.StatusSuspended {
		return state.ErrInvalidTransition
	}
	if err := m.cg.Thaw(taskID); err != nil {
		// Best-effort: if cgroup was already removed, still resume the FSM.
		if !isNotExist(err) {
			return err
		}
	}
	if err := st.Transition(state.StatusResuming, state.ActorController, "auto-resume"); err != nil {
		return err
	}
	if err := state.SaveState(taskID, st); err != nil {
		return err
	}
	if err := st.Transition(state.StatusRunning, state.ActorController, "resumed"); err != nil {
		return err
	}
	if err := state.SaveState(taskID, st); err != nil {
		return err
	}
	// The task is Running again: restart its idle countdown so a resumed
	// task auto-pauses once more when it goes idle. Without this, one
	// suspend/resume cycle permanently exempted the task from autopause.
	// Tasks without a positive idle_timeout stay unarmed, as everywhere
	// else. st is the freshly saved Running state, so IdleTimeout is the
	// persisted lifecycle config for this task.
	if d, derr := time.ParseDuration(st.IdleTimeout); derr == nil && d > 0 {
		m.Arm(taskID, d)
	}
	return nil
}

// pauseRetryDelay is how long autopause waits before retrying after a
// genuine (non-ENOENT) freeze failure.
const pauseRetryDelay = 30 * time.Second

func (m *Manager) pause(taskID string, gen uint64) {
	m.mu.Lock()
	if cur, ok := m.gens[taskID]; !ok || cur != gen {
		// Superseded by a newer Arm/Reset or a Disarm; do nothing.
		m.mu.Unlock()
		return
	}
	// Snapshot the cancel epoch together with claiming the schedule: any
	// Arm/Disarm that lands while the (slow) pause work below runs bumps it,
	// which rearmRetry checks before re-scheduling.
	epoch := m.epochs[taskID]
	// Claim the schedule before doing the (slow) pause work below, so a
	// concurrent Arm cannot double-fire and a later Disarm finds no stale
	// entry. The map entries are removed; the generation check above has
	// already authorized this callback.
	delete(m.timers, taskID)
	delete(m.gens, taskID)
	m.mu.Unlock()

	st, err := state.LoadState(taskID)
	if err != nil {
		return
	}
	if st.Status != state.StatusRunning {
		return
	}
	// Best-effort freeze: if the cgroup is not present (e.g. tests, or the
	// task exited between Load and Freeze) still transition. A genuine
	// freeze failure (EACCES, EIO, ...) must NOT persist Suspended for a
	// task that is still running; re-schedule the idle timer and skip the
	// transition so autopause retries later instead of going permanently
	// silent.
	if err := m.cg.Freeze(taskID); err != nil && !isNotExist(err) {
		m.rearmRetry(taskID, epoch)
		return
	}
	m.commitPause(taskID, epoch, st)
}

// commitPause persists the Suspended transition for an already-frozen task.
// Two hazards are reconciled on the way in:
//
//   - A Reset/Disarm that landed while the freeze was running bumped the
//     cancel epoch; the task must stay running. Thaw (the freeze above may
//     have succeeded) and let the new schedule govern.
//   - A transition or persistence failure must not leave the task frozen
//     while on disk it is still Running with no timer armed — that state
//     never self-heals. Thaw and schedule a retry via rearmRetry (which
//     skips the retry if the epoch moved on).
func (m *Manager) commitPause(taskID string, epoch uint64, st *state.ContainerState) {
	if !m.epochCurrent(taskID, epoch) {
		m.thawBestEffort(taskID)
		return
	}
	if err := st.Transition(state.StatusSuspended, state.ActorSystem, "idle timeout"); err != nil {
		m.abortPause(taskID, epoch)
		return
	}
	if err := state.SaveState(taskID, st); err != nil {
		m.abortPause(taskID, epoch)
	}
}

// epochCurrent reports whether the task's cancel epoch still equals epoch,
// i.e. no Arm/Reset/Disarm has intervened since the pause snapshot.
func (m *Manager) epochCurrent(taskID string, epoch uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epochs[taskID] == epoch
}

// abortPause unwinds a pause that froze the task but could not commit
// Suspended (FSM conflict or state persistence failure): thaw so the task
// is not left frozen-but-Running, then retry later — rearmRetry re-checks
// the epoch under one lock hold, so a newer schedule is never clobbered.
func (m *Manager) abortPause(taskID string, epoch uint64) {
	m.thawBestEffort(taskID)
	m.rearmRetry(taskID, epoch)
}

// thawBestEffort releases the freezer for taskID. A missing cgroup (task
// exited, tests) is fine; other errors have no remedy at this layer — the
// retry path or an explicit resume is the recovery route.
func (m *Manager) thawBestEffort(taskID string) {
	_ = m.cg.Thaw(taskID)
}

// rearmRetry schedules a pause retry for a failed freeze, but only if the
// task's cancel epoch still equals the one captured when the pause started.
// Without this, a Reset (fresh idle window) or Disarm that lands while the
// pause was failing to freeze would be silently clobbered by the retry
// Arm — or resurrect an explicitly disarmed task. The epoch check and the
// re-Arm happen under one lock hold, so no Reset/Disarm can slip between
// them.
func (m *Manager) rearmRetry(taskID string, epoch uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.epochs[taskID] != epoch {
		// Arm/Disarm intervened after this pause started: its schedule
		// (or its absence, after Disarm) governs — do not touch it.
		return
	}
	m.armLocked(taskID, pauseRetryDelay)
}
