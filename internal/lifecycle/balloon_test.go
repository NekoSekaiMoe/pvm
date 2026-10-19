package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	"uml-container/internal/cgroup"
	"uml-container/internal/state"
)

// setupBalloon creates a throwaway cgroup root holding the given memory.max /
// memory.current for id, and points state.RootDir at a temp dir holding a
// Suspended state for the same id.
func setupBalloon(t *testing.T, id, memMax, memCur string) (*Manager, *cgroup.Manager) {
	t.Helper()
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })

	cgRoot := t.TempDir()
	cgPath := filepath.Join(cgRoot, id)
	if err := os.MkdirAll(cgPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgPath, "memory.max"), []byte(memMax), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgPath, "memory.current"), []byte(memCur), 0o644); err != nil {
		t.Fatal(err)
	}
	cg := &cgroup.Manager{CgroupRoot: cgRoot}

	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusSuspended}
	if err := state.SaveState(id, st); err != nil {
		t.Fatal(err)
	}
	return New(cg), cg
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBalloonPauseLowersAndRestores(t *testing.T) {
	const id = "balloon1"
	m, cg := setupBalloon(t, id, "1073741824", "268435456") // 1G limit, 256M used

	if err := m.BalloonPause(id); err != nil {
		t.Fatalf("balloon: %v", err)
	}
	maxFile := filepath.Join(cg.CgroupRoot, id, "memory.max")
	if got := readFile(t, maxFile); got != "268435456" {
		t.Fatalf("memory.max after balloon = %q, want current usage", got)
	}
	// The prior limit is recorded for the resume.
	st, _ := state.LoadState(id)
	if st.Metadata[pauseMemoryMaxKey] != "1073741824" {
		t.Fatalf("prior limit not recorded: %+v", st.Metadata)
	}

	// Ballooning again is a no-op (idempotent).
	if err := m.BalloonPause(id); err != nil {
		t.Fatalf("second balloon: %v", err)
	}
	if got := readFile(t, maxFile); got != "268435456" {
		t.Fatalf("idempotent balloon changed max to %q", got)
	}

	// Restore puts the original limit back and clears the marker.
	m.RestorePauseBalloon(id, st)
	if got := readFile(t, maxFile); got != "1073741824" {
		t.Fatalf("memory.max after restore = %q, want 1G", got)
	}
	if _, ok := st.Metadata[pauseMemoryMaxKey]; ok {
		t.Fatalf("marker not cleared: %+v", st.Metadata)
	}
}

func TestBalloonPauseUnlimitedLimit(t *testing.T) {
	const id = "balloon2"
	m, cg := setupBalloon(t, id, "max", "134217728") // unlimited, 128M used

	if err := m.BalloonPause(id); err != nil {
		t.Fatalf("balloon: %v", err)
	}
	maxFile := filepath.Join(cg.CgroupRoot, id, "memory.max")
	if got := readFile(t, maxFile); got != "134217728" {
		t.Fatalf("unlimited max after balloon = %q, want current usage", got)
	}
	st, _ := state.LoadState(id)
	if st.Metadata[pauseMemoryMaxKey] != "-1" {
		t.Fatalf("unlimited prior limit recorded as %q, want -1", st.Metadata[pauseMemoryMaxKey])
	}
	// Restore returns the cgroup to unlimited ("max").
	m.RestorePauseBalloon(id, st)
	if got := readFile(t, maxFile); got != "max" {
		t.Fatalf("memory.max after restore = %q, want max", got)
	}
}

func TestBalloonPauseOnlyOnSuspended(t *testing.T) {
	const id = "balloon3"
	m, cg := setupBalloon(t, id, "1073741824", "268435456")
	// Flip the task back to Running: ballooning must not touch it.
	st, _ := state.LoadState(id)
	if err := st.Transition(state.StatusResuming, state.ActorSystem, "t"); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition(state.StatusRunning, state.ActorSystem, "t"); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveState(id, st); err != nil {
		t.Fatal(err)
	}
	if err := m.BalloonPause(id); err != nil {
		t.Fatalf("balloon on running: %v", err)
	}
	if got := readFile(t, filepath.Join(cg.CgroupRoot, id, "memory.max")); got != "1073741824" {
		t.Fatalf("running task ballooned: max=%q", got)
	}
}

func TestBalloonPauseNoCgroupIsSkipped(t *testing.T) {
	const id = "balloon4"
	dir := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = dir
	t.Cleanup(func() { state.RootDir = origRoot })
	st := &state.ContainerState{ID: id, Name: id, Status: state.StatusSuspended}
	if err := state.SaveState(id, st); err != nil {
		t.Fatal(err)
	}
	// Point at an empty cgroup root: no cgroup dir for id.
	m := New(&cgroup.Manager{CgroupRoot: t.TempDir()})
	if err := m.BalloonPause(id); err == nil {
		t.Fatal("expected an error when the cgroup is missing")
	}
	// The state must be unchanged (no marker written).
	got, _ := state.LoadState(id)
	if _, ok := got.Metadata[pauseMemoryMaxKey]; ok {
		t.Fatalf("marker written without a cgroup: %+v", got.Metadata)
	}
}
