package lifecycle

import (
	"testing"

	"uml-container/internal/state"
)

func TestDeepPauseModeBookkeeping(t *testing.T) {
	state.RootDir = t.TempDir()
	m := New(nil)
	m.SetDeepPause("t1", true)
	if !m.deepPauseWanted("t1") {
		t.Fatal("deep mode must be recorded")
	}
	m.SetDeepPause("t1", false)
	if m.deepPauseWanted("t1") {
		t.Fatal("deep mode must be clearable")
	}
	if m.deepPauseWanted("unknown") {
		t.Fatal("unknown tasks default to shallow")
	}
}

func TestIsDeepPausedRequiresState(t *testing.T) {
	state.RootDir = t.TempDir()
	if IsDeepPaused("ghost") {
		t.Fatal("missing state is not deep-paused")
	}
	st := &state.ContainerState{ID: "dp", Status: state.StatusRunning}
	state.SaveState("dp", st)
	if IsDeepPaused("dp") {
		t.Fatal("Running task is not deep-paused")
	}
	st.Status = state.StatusSuspended
	st.Metadata = map[string]string{"pause_mode": "deep"}
	state.SaveState("dp", st)
	if !IsDeepPaused("dp") {
		t.Fatal("Suspended+deep metadata must report deep-paused")
	}
}
