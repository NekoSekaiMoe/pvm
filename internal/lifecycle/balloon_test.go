package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"uml-container/internal/cgroup"
	"uml-container/internal/state"
)

// Regular files model cgroup controls without touching the host's cgroups.
func newPauseFixture(t *testing.T, status state.Status) (*Manager, string) {
	t.Helper()
	origRoot := state.Root()
	state.SetRoot(t.TempDir())
	t.Cleanup(func() { state.SetRoot(origRoot) })
	const id = "pause-task"
	if err := state.SaveState(id, &state.ContainerState{ID: id, Status: status}); err != nil {
		t.Fatal(err)
	}
	cg := &cgroup.Manager{CgroupRoot: t.TempDir()}
	if err := os.MkdirAll(filepath.Join(cg.CgroupRoot, id), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New(cg)
	writePauseControl(t, m, id, "cgroup.freeze", "1")
	writePauseControl(t, m, id, "memory.max", "1024")
	writePauseControl(t, m, id, "memory.current", "256")
	return m, id
}

func writePauseControl(t *testing.T, m *Manager, id, name, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(m.cg.CgroupRoot, id, name), []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertPauseControl(t *testing.T, m *Manager, id, name, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(m.cg.CgroupRoot, id, name))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func TestBalloonPauseResumeRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name, limit, usage, paused, recorded string
	}{
		{"finite", "1024", "256", "256", "1024"},
		{"unlimited", "max", "256", "256", "-1"},
		{"never raises limit", "128", "256", "128", "128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, id := newPauseFixture(t, state.StatusSuspended)
			writePauseControl(t, m, id, "memory.max", tc.limit)
			writePauseControl(t, m, id, "memory.current", tc.usage)
			if err := m.BalloonPause(id); err != nil {
				t.Fatal(err)
			}
			assertPauseControl(t, m, id, "memory.max", tc.paused)
			// Repeated pauses must preserve the original limit on disk.
			if err := m.BalloonPause(id); err != nil {
				t.Fatal(err)
			}
			st, err := state.LoadState(id)
			if err != nil {
				t.Fatal(err)
			}
			if got := st.Metadata[pauseMemoryMaxKey]; got != tc.recorded {
				t.Fatalf("saved original limit = %q, want %q", got, tc.recorded)
			}
			// A fresh manager must restore from persisted metadata after restart.
			if err := New(m.cg).Resume(id); err != nil {
				t.Fatal(err)
			}
			assertPauseControl(t, m, id, "memory.max", tc.limit)
			assertPauseControl(t, m, id, "cgroup.freeze", "0")
			st, err = state.LoadState(id)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := st.Metadata[pauseMemoryMaxKey]; ok || st.Status != state.StatusRunning {
				t.Fatalf("resume did not clear balloon and reach Running: %+v", st)
			}
		})
	}
}

func TestBalloonPauseSkipsRunningTask(t *testing.T) {
	m, id := newPauseFixture(t, state.StatusRunning)
	if err := m.BalloonPause(id); err != nil {
		t.Fatal(err)
	}
	assertPauseControl(t, m, id, "memory.max", "1024")
}

func TestBalloonPauseSaveFailureRestoresLimit(t *testing.T) {
	m, id := newPauseFixture(t, state.StatusSuspended)
	origSave := saveState
	wantErr := errors.New("injected persistence failure")
	saveState = func(string, *state.ContainerState) error { return wantErr }
	t.Cleanup(func() { saveState = origSave })
	if err := m.BalloonPause(id); !errors.Is(err, wantErr) {
		t.Fatalf("BalloonPause = %v, want %v", err, wantErr)
	}
	assertPauseControl(t, m, id, "memory.max", "1024")
	st, err := state.LoadState(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Metadata[pauseMemoryMaxKey]; ok {
		t.Fatal("failed balloon persisted its marker")
	}
}
