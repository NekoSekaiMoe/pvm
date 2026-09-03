package snapshot

import (
	"testing"

	"uml-container/internal/state"
)

// The suite never requires a real CRIU: absent binaries must degrade
// explicitly, and the memory_state marker must land in the snapshot
// metadata so restores can tell full from degraded apart.
func TestEventSnapshotMemoryStateMarkers(t *testing.T) {
	oldRoot := state.RootDir
	state.RootDir = t.TempDir()
	t.Cleanup(func() { state.RootDir = oldRoot })

	// Running task with a pid: no criu on this host -> degraded.
	mkdirState(t, "t-mem", state.StatusRunning, 4242)
	snap, err := CreateEventSnapshot("t-mem", "evt-1", "", map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	want := string(MemoryDegraded)
	if CRIUBin() != "" {
		// A host WITH criu may succeed or fail; both are valid outcomes,
		// but the marker must be one of the two, never missing.
		if snap.Metadata["memory_state"] != string(MemoryFull) && snap.Metadata["memory_state"] != string(MemoryDegraded) {
			t.Fatalf("memory_state marker missing: %+v", snap.Metadata)
		}
		want = snap.Metadata["memory_state"]
	}
	if snap.Metadata["memory_state"] != want || snap.Metadata["k"] != "v" {
		t.Fatalf("metadata mutated wrongly: %+v", snap.Metadata)
	}

	// Stopped task (no live pid): n/a marker.
	mkdirState(t, "t-stopped", state.StatusSuspended, 0)
	snap2, err := CreateEventSnapshot("t-stopped", "evt-2", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap2.Metadata["memory_state"] != string(MemoryNotAttempt) {
		t.Fatalf("stopped task must be n/a: %+v", snap2.Metadata)
	}
}

func TestDumpMemoryWithoutCRIU(t *testing.T) {
	if CRIUBin() != "" {
		t.Skip("host has criu; degraded-path assertion only runs without it")
	}
	if err := DumpMemory(999, t.TempDir(), true); err == nil || err != ErrCRIUUnavailable {
		t.Fatalf("expected ErrCRIUUnavailable, got %v", err)
	}
}

// mkdirState seeds a task state file under the CURRENT state root.
func mkdirState(t *testing.T, id string, status state.Status, pid int) {
	t.Helper()
	if err := state.SaveState(id, &state.ContainerState{ID: id, Name: id, Status: status, PID: pid}); err != nil {
		t.Fatal(err)
	}
}

func TestDumpMemoryArgsIncremental(t *testing.T) {
	t.Run("base dump", func(t *testing.T) {
		base := DumpMemoryArgs(42, "/s/criu", "", true)
		for _, want := range []string{"--tree", "42", "--images-dir", "/s/criu", "--leave-running"} {
			if !contains(base, want) {
				t.Fatalf("base args missing %q: %v", want, base)
			}
		}
		for _, bad := range []string{"--track-mem", "--prev-images-dir"} {
			if contains(base, bad) {
				t.Fatalf("base args must not carry %q", bad)
			}
		}
	})
	t.Run("incremental dump", func(t *testing.T) {
		inc := DumpMemoryArgs(42, "/s/criu", "../snap-1/criu", false)
		if !contains(inc, "--track-mem") || !contains(inc, "--prev-images-dir") || !contains(inc, "../snap-1/criu") {
			t.Fatalf("incremental args = %v", inc)
		}
		if contains(inc, "--leave-running") {
			t.Fatal("checkpoint-and-stop must not leave running")
		}
	})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// prevImagesRel: the relative --prev-images-dir must be computed against
// the criu IMAGES dir (the "criu" subdir) and must keep the parent inside
// the task's snapshots root. Regression: the old base (the snapshot dir)
// rejected every sibling, so incremental dumps never happened.
func TestPrevImagesRel(t *testing.T) {
	cases := []struct {
		name      string
		targetDir string
		snapDir   string
		prev      string
		want      string
	}{
		{
			name:      "sibling snapshot chains with ..",
			targetDir: "/s/t1/snapshots/snap-2",
			snapDir:   "/s/t1/snapshots",
			prev:      "/s/t1/snapshots/snap-1/criu",
			want:      "../../snap-1/criu",
		},
		{
			name:      "identical images dir resolves to dot",
			targetDir: "/s/t1/snapshots/snap-2",
			snapDir:   "/s/t1/snapshots",
			prev:      "/s/t1/snapshots/snap-2/criu",
			want:      ".",
		},
		{
			name:      "escape outside the snapshots root rejected",
			targetDir: "/s/t1/snapshots/snap-2",
			snapDir:   "/s/t1/snapshots",
			prev:      "/s/t2/snapshots/snap-1/criu",
			want:      "",
		},
		{
			name:      "far escape rejected",
			targetDir: "/s/t1/snapshots/snap-2",
			snapDir:   "/s/t1/snapshots",
			prev:      "/etc/criu",
			want:      "",
		},
		{
			name:      "empty prev is a full dump",
			targetDir: "/s/t1/snapshots/snap-2",
			snapDir:   "/s/t1/snapshots",
			prev:      "",
			want:      "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := prevImagesRel(tc.targetDir, tc.snapDir, tc.prev); got != tc.want {
				t.Fatalf("prevImagesRel = %q, want %q", got, tc.want)
			}
		})
	}
}

// CRIUBin: an explicit override that cannot run is "unavailable" — this is
// also what lets integration tests isolate a server from a host criu.
func TestCRIUBinOverrideMustExist(t *testing.T) {
	t.Setenv("PVM_CRIU_BIN", "/nonexistent/criu-definitely-not-here")
	if got := CRIUBin(); got != "" {
		t.Fatalf("unusable override must resolve to empty, got %q", got)
	}
}
