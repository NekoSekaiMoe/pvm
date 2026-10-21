package lifecycle

import (
	"errors"
	"testing"

	"uml-container/internal/state"
)

type testQuotaHooks struct {
	suspend func(string) (bool, error)
	resume  func(string) (bool, error)
}

func (h testQuotaHooks) SuspendByTask(id string) (bool, error) { return h.suspend(id) }
func (h testQuotaHooks) ResumeByTask(id string) (bool, error)  { return h.resume(id) }

func TestPauseReleasesQuotaAfterCommit(t *testing.T) {
	m, id := newPauseFixture(t, state.StatusRunning)
	released := false
	m.SetQuotaHooks(testQuotaHooks{
		suspend: func(taskID string) (bool, error) {
			if taskID != id || mustStatus(t, id) != state.StatusSuspended {
				t.Fatal("quota released before pause was durable")
			}
			assertPauseControl(t, m, id, "cgroup.freeze", "1")
			released = true
			return true, errors.New("bookkeeping unavailable")
		},
	})
	st, err := state.LoadState(id)
	if err != nil {
		t.Fatal(err)
	}
	m.commitPause(id, 0, st)
	if !released || mustStatus(t, id) != state.StatusSuspended {
		t.Fatal("committed pause must release quota even if bookkeeping fails")
	}
}

func TestResumeQuotaRefusalLeavesTaskFrozen(t *testing.T) {
	m, id := newPauseFixture(t, state.StatusSuspended)
	if err := m.BalloonPause(id); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("quota exceeded")
	reserved := false
	m.SetQuotaHooks(testQuotaHooks{
		resume: func(taskID string) (bool, error) {
			if taskID != id || mustStatus(t, id) != state.StatusSuspended {
				t.Fatal("quota reserved for the wrong task or after resume")
			}
			assertPauseControl(t, m, id, "cgroup.freeze", "1")
			reserved = true
			return false, wantErr
		},
		suspend: func(string) (bool, error) {
			t.Fatal("refused reservation must not be released")
			return false, nil
		},
	})
	if err := m.Resume(id); !errors.Is(err, wantErr) || !reserved {
		t.Fatalf("Resume = %v, reservation attempted = %v", err, reserved)
	}
	assertPauseControl(t, m, id, "cgroup.freeze", "1")
	assertPauseControl(t, m, id, "memory.max", "256")
	if got := mustStatus(t, id); got != state.StatusSuspended {
		t.Fatalf("refused resume changed status to %q", got)
	}
}

func TestResumePersistenceFailureReleasesQuota(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(map[int]string{1: "resuming", 2: "running"}[failAt], func(t *testing.T) {
			m, id := newPauseFixture(t, state.StatusSuspended)
			reserved, released := 0, 0
			m.SetQuotaHooks(testQuotaHooks{
				resume: func(string) (bool, error) {
					assertPauseControl(t, m, id, "cgroup.freeze", "1")
					reserved++
					return true, nil
				},
				suspend: func(string) (bool, error) {
					assertPauseControl(t, m, id, "cgroup.freeze", "1")
					released++
					return true, nil
				},
			})
			origSave := saveState
			wantErr := errors.New("injected persistence failure")
			calls := 0
			saveState = func(taskID string, st *state.ContainerState) error {
				calls++
				if calls == failAt {
					return wantErr
				}
				return origSave(taskID, st)
			}
			t.Cleanup(func() { saveState = origSave })
			if err := m.Resume(id); !errors.Is(err, wantErr) {
				t.Fatalf("Resume = %v, want %v", err, wantErr)
			}
			if reserved != 1 || released != 1 || mustStatus(t, id) != state.StatusSuspended {
				t.Fatalf("failed resume: reserved=%d released=%d status=%s", reserved, released, mustStatus(t, id))
			}
			// Retrying reserves again and keeps the successful reservation.
			saveState = origSave
			if err := m.Resume(id); err != nil {
				t.Fatal(err)
			}
			if reserved != 2 || released != 1 || mustStatus(t, id) != state.StatusRunning {
				t.Fatal("successful retry did not retain its reservation")
			}
			assertPauseControl(t, m, id, "cgroup.freeze", "0")
		})
	}
}
