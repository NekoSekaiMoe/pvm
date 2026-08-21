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
	return state.SaveState(taskID, st)
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
		m.Arm(taskID, pauseRetryDelay)
		return
	}
	_ = st.Transition(state.StatusSuspended, state.ActorSystem, "idle timeout")
	_ = state.SaveState(taskID, st)
}
