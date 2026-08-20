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
	mu     sync.Mutex
	timers map[string]*time.Timer
	cg     *cgroup.Manager
}

// New creates a Manager. cg may be nil to use the default cgroup root.
func New(cg *cgroup.Manager) *Manager {
	if cg == nil {
		cg = cgroup.NewManager()
	}
	return &Manager{
		timers: make(map[string]*time.Timer),
		cg:     cg,
	}
}

// Arm starts (or resets) the idle countdown for taskID. When d elapses
// without a Reset/Disarm, the task is frozen and moved to Suspended.
// d <= 0 disables autopause for this task.
func (m *Manager) Arm(taskID string, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.timers[taskID]; ok {
		old.Stop()
		delete(m.timers, taskID)
	}
	if d <= 0 {
		return
	}
	m.timers[taskID] = time.AfterFunc(d, func() { m.pause(taskID) })
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

func (m *Manager) pause(taskID string) {
	st, err := state.LoadState(taskID)
	if err != nil {
		return
	}
	if st.Status != state.StatusRunning {
		return
	}
	// Best-effort freeze; if cgroup not present (e.g. test), still transition.
	_ = m.cg.Freeze(taskID)
	_ = st.Transition(state.StatusSuspended, state.ActorSystem, "idle timeout")
	_ = state.SaveState(taskID, st)

	m.mu.Lock()
	delete(m.timers, taskID)
	m.mu.Unlock()
}
