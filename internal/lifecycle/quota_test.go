package lifecycle

import (
	"errors"
	"testing"

	"uml-container/internal/cgroup"
	"uml-container/internal/state"
)

// fakeQuota records the calls the lifecycle makes on the seam.
type fakeQuota struct {
	suspended []string
	resumed   []string
	resumeErr error
}

func (f *fakeQuota) SuspendByTask(taskID string) (bool, error) {
	f.suspended = append(f.suspended, taskID)
	return true, nil
}

func (f *fakeQuota) ResumeByTask(taskID string) (bool, error) {
	f.resumed = append(f.resumed, taskID)
	return f.resumeErr == nil, f.resumeErr
}

func setupQuotaTask(t *testing.T, id string) *Manager {
	t.Helper()
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })

	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusRunning}
	if err := state.SaveState(id, st); err != nil {
		t.Fatal(err)
	}
	return New(&cgroup.Manager{CgroupRoot: t.TempDir()})
}

// TestResumeReleasesQuotaOnFailure: when a resume cannot complete, the
// re-reserved quota must be given back so the tenant is not charged for a
// task that is still suspended.
func TestResumeReleasesQuotaOnFailure(t *testing.T) {
	const id = "quota-task-1"
	m := setupQuotaTask(t, id)
	fq := &fakeQuota{}
	m.SetQuotaHooks(fq)

	// The task must be Suspended for Resume to proceed.
	st, _ := state.LoadState(id)
	if err := st.Transition(state.StatusSuspended, state.ActorHuman, "prep"); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveState(id, st); err != nil {
		t.Fatal(err)
	}
	// Force the resume's first persist to fail: Resume must then roll back
	// and re-release the reservation it just made.
	origSave := saveState
	saveState = func(string, *state.ContainerState) error { return errors.New("disk full") }
	t.Cleanup(func() { saveState = origSave })
	if err := m.Resume(id); err == nil {
		t.Fatal("expected the injected save failure to abort the resume")
	}
	if len(fq.resumed) != 1 {
		t.Fatalf("resume hook called %d times, want 1", len(fq.resumed))
	}
	if len(fq.suspended) != 1 || fq.suspended[0] != id {
		t.Fatalf("quota was not released after the failed resume: %+v", fq.suspended)
	}
}

// TestResumeBlockedByQuota: a quota refusal aborts the resume BEFORE the
// runtime is touched, leaving the task suspended and the guest frozen.
func TestResumeBlockedByQuota(t *testing.T) {
	const id = "quota-task-2"
	m := setupQuotaTask(t, id)
	fq := &fakeQuota{resumeErr: errors.New("quota exhausted")}
	m.SetQuotaHooks(fq)

	st, _ := state.LoadState(id)
	if err := st.Transition(state.StatusSuspended, state.ActorHuman, "prep"); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveState(id, st); err != nil {
		t.Fatal(err)
	}
	if err := m.Resume(id); err == nil {
		t.Fatal("expected the quota refusal to abort the resume")
	}
	got, _ := state.LoadState(id)
	if got.Status != state.StatusSuspended {
		t.Fatalf("status = %s, want Suspended after a refused resume", got.Status)
	}
}

// TestCommitPauseReleasesQuota: a durable autopause releases the tenant's
// memory reservation.
func TestCommitPauseReleasesQuota(t *testing.T) {
	const id = "quota-task-3"
	m := setupQuotaTask(t, id)
	fq := &fakeQuota{}
	m.SetQuotaHooks(fq)

	st, _ := state.LoadState(id)
	if err := st.Transition(state.StatusSuspended, state.ActorSystem, "idle timeout"); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveState(id, st); err != nil {
		t.Fatal(err)
	}
	m.releaseQuota(id)
	if len(fq.suspended) != 1 || fq.suspended[0] != id {
		t.Fatalf("pause did not release quota: %+v", fq.suspended)
	}
}
