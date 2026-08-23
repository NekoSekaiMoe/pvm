// Spec-alignment guard tests for Rollback (todo #3, disk edition of the
// CubeShim start_vm config guard): a task whose spec fingerprint changed
// since the snapshot must refuse to roll back (unless forced), and the
// refusal must leave state untouched.

package snapshot

import (
	"errors"
	"testing"

	"uml-container/internal/state"
)

func newRollbackTask(t *testing.T, specFP string) {
	t.Helper()
	state.RootDir = t.TempDir()
	if err := state.SaveState("rbguard1", &state.ContainerState{
		ID:     "rbguard1",
		Name:   "rbguard1",
		Status: state.StatusRunning,
		SpecFP: specFP,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackSpecMismatchRefused(t *testing.T) {
	newRollbackTask(t, "fp-A")
	snap, err := CreateEventSnapshot("rbguard1", "evt1", "hash", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the task being re-created under a different TaskSpec.
	if err := state.SaveState("rbguard1", &state.ContainerState{
		ID:     "rbguard1",
		Name:   "rbguard1",
		Status: state.StatusRunning,
		SpecFP: "fp-B",
	}); err != nil {
		t.Fatal(err)
	}

	err = Rollback("rbguard1", snap.ID)
	if !errors.Is(err, ErrSpecMismatch) {
		t.Fatalf("expected ErrSpecMismatch, got %v", err)
	}

	// Refusal must not touch current state.
	st, lerr := state.LoadState("rbguard1")
	if lerr != nil {
		t.Fatal(lerr)
	}
	if st.SpecFP != "fp-B" {
		t.Fatalf("refused rollback mutated state: specFP=%q", st.SpecFP)
	}

	// Force overrides the guard and restores the recorded status.
	if err := RollbackWithForce("rbguard1", snap.ID, true); err != nil {
		t.Fatalf("forced rollback: %v", err)
	}
}

func TestRollbackSpecAlignedSucceeds(t *testing.T) {
	newRollbackTask(t, "fp-A")
	snap, err := CreateEventSnapshot("rbguard1", "evt1", "hash", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Same fingerprint (or task state rewritten identically) -> rollback passes.
	if err := state.SaveState("rbguard1", &state.ContainerState{
		ID:     "rbguard1",
		Name:   "rbguard1",
		Status: state.StatusReady,
		SpecFP: "fp-A",
	}); err != nil {
		t.Fatal(err)
	}
	if err := Rollback("rbguard1", snap.ID); err != nil {
		t.Fatalf("aligned rollback should pass: %v", err)
	}
}

func TestRollbackLegacyNoFingerprintSkipsGuard(t *testing.T) {
	// Legacy containers carry no SpecFP on either side; the guard must not
	// fire and lock them out of rollback entirely.
	newRollbackTask(t, "")
	snap, err := CreateEventSnapshot("rbguard1", "evt1", "hash", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Rollback("rbguard1", snap.ID); err != nil {
		t.Fatalf("legacy rollback should pass: %v", err)
	}
}
