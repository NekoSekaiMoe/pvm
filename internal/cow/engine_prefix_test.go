package cow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEngine_CreateVolume_RejectsSnapshotPrefix guards the reserved "snap-"
// namespace. volumePath(name) is <root>/<name>.qcow2 while snapshotPath(name)
// is <root>/snap-<name>.qcow2, so a volume named "snap-x" would live at the
// same file as snapshot "x" — and DeleteSnapshot("x") would delete the
// volume. CreateVolume must refuse the prefix outright.
func TestEngine_CreateVolume_RejectsSnapshotPrefix(t *testing.T) {
	e := NewEngine(t.TempDir())
	for _, name := range []string{"snap-x", "snap-data", "snap-123"} {
		t.Run(name, func(t *testing.T) {
			_, err := e.CreateVolume(name, 1<<20)
			if err == nil || !strings.Contains(err.Error(), "snap-") {
				t.Fatalf("CreateVolume(%q) err = %v, want reserved-snap--prefix rejection", name, err)
			}
			// The rejected create must leave nothing behind — neither the
			// volume file nor a snapshot slot.
			if _, serr := os.Stat(filepath.Join(e.root, name+".qcow2")); serr == nil {
				t.Fatalf("rejected volume %q nevertheless created %s", name, filepath.Join(e.root, name+".qcow2"))
			}
		})
	}
	// A snapshot name that merely CONTAINS the prefix elsewhere is still
	// fine and must not be affected by the volume-side guard: creating
	// snapshot "snap-x" (from volume "v") maps to snap-snap-x.qcow2, which
	// cannot collide with any volume.
	if _, err := e.CreateVolume("v", 1<<20); err != nil {
		t.Fatalf("create volume v: %v", err)
	}
	if _, err := e.CreateSnapshot("v", "snap-x"); err != nil {
		t.Fatalf("create snapshot named snap-x: %v", err)
	}
}

// TestEngine_DeleteSnapshot_CannotDeleteVolume verifies DeleteSnapshot only
// ever removes snapshot files: with volume "x" (<root>/x.qcow2) and snapshot
// "x" (<root>/snap-x.qcow2) coexisting, deleting the snapshot must leave the
// volume intact. Combined with the CreateVolume guard (no volume can occupy
// a snap-*.qcow2 path), DeleteSnapshot can never reach a volume file.
func TestEngine_DeleteSnapshot_CannotDeleteVolume(t *testing.T) {
	e := NewEngine(t.TempDir())
	if _, err := e.CreateVolume("x", 1<<20); err != nil {
		t.Fatalf("create volume: %v", err)
	}
	if _, err := e.CreateSnapshot("x", "x"); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	volPath := e.volumePath("x")
	snapPath := e.snapshotPath("x")
	if err := e.DeleteSnapshot("x"); err != nil {
		t.Fatalf("delete snapshot: %v", err)
	}
	if _, err := os.Stat(snapPath); !os.IsNotExist(err) {
		t.Fatalf("snapshot file %s must be gone after DeleteSnapshot (stat err=%v)", snapPath, err)
	}
	if _, err := os.Stat(volPath); err != nil {
		t.Fatalf("volume file %s must survive DeleteSnapshot: %v", volPath, err)
	}
	if _, err := e.GetVolumeInfo("x"); err != nil {
		t.Fatalf("volume x must still be readable after DeleteSnapshot: %v", err)
	}
}

// TestEngine_ListVolumes_NormalNames is the no-regression guard for the
// snap- prefix rejection: plain volume names (including ones containing
// "snap" without the dash prefix) must keep listing, and snapshots must stay
// excluded from the volume listing.
func TestEngine_ListVolumes_NormalNames(t *testing.T) {
	e := NewEngine(t.TempDir())
	want := []string{"alpha", "beta-vol", "snapless"}
	for _, name := range want {
		if _, err := e.CreateVolume(name, 1<<20); err != nil {
			t.Fatalf("create volume %s: %v", name, err)
		}
	}
	if _, err := e.CreateSnapshot("alpha", "s0"); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	vols, err := e.ListVolumes()
	if err != nil {
		t.Fatalf("list volumes: %v", err)
	}
	got := make(map[string]bool, len(vols))
	for _, v := range vols {
		got[v.Name] = true
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("volume %s missing from listing: %v", name, got)
		}
	}
	if len(vols) != len(want) {
		t.Errorf("listing returned %d volumes, want %d (snapshot leaked in?): %+v", len(vols), len(want), vols)
	}
}
