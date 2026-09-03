package lifecycle

import (
	"testing"

	"uml-container/internal/state"
)

func TestDeepPauseModeBookkeeping(t *testing.T) {
	state.RootDir = t.TempDir()
	m := New(nil)
	cases := []struct {
		name string
		set  bool
		want bool
	}{
		{"arm records deep mode", true, true},
		{"disarm clears deep mode", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m.SetDeepPause("t1", tc.set)
			if got := m.deepPauseWanted("t1"); got != tc.want {
				t.Fatalf("deepPauseWanted = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("unknown tasks default to shallow", func(t *testing.T) {
		if m.deepPauseWanted("unknown") {
			t.Fatal("unknown tasks default to shallow")
		}
	})
}

func TestIsDeepPausedRequiresState(t *testing.T) {
	state.RootDir = t.TempDir()
	cases := []struct {
		name string
		id   string
		mk   func(id string) *state.ContainerState
		want bool
	}{
		{"missing state is not deep-paused", "ghost", nil, false},
		{"Running task is not deep-paused", "run", func(id string) *state.ContainerState {
			return &state.ContainerState{ID: id, Status: state.StatusRunning}
		}, false},
		{"plain Suspended is not deep-paused", "plain", func(id string) *state.ContainerState {
			return &state.ContainerState{ID: id, Status: state.StatusSuspended}
		}, false},
		{"Suspended+deep metadata reports deep-paused", "dp", func(id string) *state.ContainerState {
			return &state.ContainerState{ID: id, Status: state.StatusSuspended,
				Metadata: map[string]string{"pause_mode": "deep"}}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mk != nil {
				if err := state.SaveState(tc.id, tc.mk(tc.id)); err != nil {
					t.Fatal(err)
				}
			}
			if got := IsDeepPaused(tc.id); got != tc.want {
				t.Fatalf("IsDeepPaused = %v, want %v", got, tc.want)
			}
		})
	}
}
