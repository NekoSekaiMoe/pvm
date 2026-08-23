// Spec-alignment guard tests for Rollback (todo #3, disk edition of the
// CubeShim start_vm config guard): a task whose spec fingerprint changed
// since the snapshot must refuse to roll back (unless forced), and the
// refusal must leave state untouched. An unreadable/corrupt snapshot state
// copy is not "legacy": it must fail closed instead of silently bypassing
// the guard and restoring the old overlay.

package snapshot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// corruptSnapState overwrites the snapshot's state.json with invalid JSON.
func corruptSnapState(t *testing.T, snapshotID string) {
	t.Helper()
	dir, err := snapshotsDir("rbguard1")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, snapshotID, "state.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// removeSnapState deletes the snapshot's state.json entirely.
func removeSnapState(t *testing.T, snapshotID string) {
	t.Helper()
	dir, err := snapshotsDir("rbguard1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, snapshotID, "state.json")); err != nil {
		t.Fatal(err)
	}
}

// loadRollbackTask returns the persisted state for rbguard1.
func loadRollbackTask(t *testing.T) *state.ContainerState {
	t.Helper()
	st, err := state.LoadState("rbguard1")
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRollbackSpecGuard(t *testing.T) {
	scenarios := []struct {
		name string
		// currentSpecFP rewrites the task state AFTER snapshot creation,
		// simulating a task re-created under a (possibly different) spec.
		// Empty string means "keep the snapshot-time state as-is".
		currentSpecFP  string
		force          bool
		corruptState   bool // overwrite snapshot state.json with garbage
		missingState   bool // delete snapshot state.json entirely
		wantErr        bool
		wantErrIs      error  // expected sentinel, if any
		wantErrContain string // expected substring, if any
		// stateUntouched asserts the refusal left no rollback transition.
		stateUntouched bool
	}{
		{
			name:           "mismatch refused",
			currentSpecFP:  "fp-B",
			wantErr:        true,
			wantErrIs:      ErrSpecMismatch,
			stateUntouched: true,
		},
		{
			name:    "aligned succeeds",
			wantErr: false,
		},
		{
			name:          "forced overrides mismatch",
			currentSpecFP: "fp-B",
			force:         true,
			wantErr:       false,
		},
		{
			name:           "corrupt state.json fails closed",
			corruptState:   true,
			wantErr:        true,
			wantErrContain: "failed to parse snapshot state copy",
			stateUntouched: true,
		},
		{
			name:           "missing state.json fails closed",
			missingState:   true,
			wantErr:        true,
			wantErrContain: "failed to read snapshot state copy",
			stateUntouched: true,
		},
		{
			name:         "forced tolerates corrupt state.json",
			corruptState: true,
			force:        true,
			wantErr:      false,
		},
	}

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			newRollbackTask(t, "fp-A")
			snap, err := CreateEventSnapshot("rbguard1", "evt1", "hash", nil)
			if err != nil {
				t.Fatal(err)
			}

			if sc.corruptState {
				corruptSnapState(t, snap.ID)
			}
			if sc.missingState {
				removeSnapState(t, snap.ID)
			}
			if sc.currentSpecFP != "" {
				// Simulate the task being re-created under a different TaskSpec.
				if err := state.SaveState("rbguard1", &state.ContainerState{
					ID:     "rbguard1",
					Name:   "rbguard1",
					Status: state.StatusRunning,
					SpecFP: sc.currentSpecFP,
				}); err != nil {
					t.Fatal(err)
				}
			}
			// Transitions recorded before the rollback attempt; a refusal
			// must not append anything.
			before := loadRollbackTask(t)

			err = RollbackWithForce("rbguard1", snap.ID, sc.force)
			if sc.wantErr {
				if err == nil {
					t.Fatalf("expected rollback to be refused, got nil error")
				}
				if sc.wantErrIs != nil && !errors.Is(err, sc.wantErrIs) {
					t.Fatalf("expected %v, got %v", sc.wantErrIs, err)
				}
				if sc.wantErrContain != "" && !strings.Contains(err.Error(), sc.wantErrContain) {
					t.Fatalf("expected error containing %q, got %v", sc.wantErrContain, err)
				}
			} else if err != nil {
				t.Fatalf("rollback should pass: %v", err)
			}

			after := loadRollbackTask(t)
			if sc.stateUntouched {
				// Refusal must not touch current state: same fingerprint,
				// same status, no rollback transition appended — and the
				// guard runs before any overlay restore, so the disk side
				// is untouched too.
				if after.SpecFP != before.SpecFP {
					t.Fatalf("refused rollback mutated state: specFP=%q", after.SpecFP)
				}
				if len(after.Transitions) != len(before.Transitions) {
					t.Fatalf("refused rollback recorded transitions: %d -> %d",
						len(before.Transitions), len(after.Transitions))
				}
			}
		})
	}
}

// TestRollbackLegacyNoFingerprintSkipsGuard covers the legacy compatibility
// path: snapshots whose state copy parses cleanly but predates SpecFP must
// skip the guard rather than lock the task out of rollback.
func TestRollbackLegacyNoFingerprintSkipsGuard(t *testing.T) {
	newRollbackTask(t, "")
	snap, err := CreateEventSnapshot("rbguard1", "evt1", "hash", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Rollback("rbguard1", snap.ID); err != nil {
		t.Fatalf("legacy rollback should pass: %v", err)
	}
}
