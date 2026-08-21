package cow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEngine_NameValidation_BlocksTraversal verifies that volume/snapshot
// names which would escape the engine root (via "../", absolute paths, or
// separators/dots) are rejected before any path is constructed.
func TestEngine_NameValidation_BlocksTraversal(t *testing.T) {
	e := NewEngine(t.TempDir())
	bad := []string{
		"",
		"../../etc/cron.d/x",
		"..",
		"../",
		"a/b",
		"/tmp/abs",
		"a.b",
		"a b",
		strings.Repeat("x", 129),
	}
	for _, name := range bad {
		if _, err := e.CreateVolume(name, 1<<20); err == nil {
			t.Fatalf("CreateVolume accepted traversal name %q", name)
		}
		if err := e.DeleteVolume(name); err == nil {
			t.Fatalf("DeleteVolume accepted traversal name %q", name)
		}
		if _, err := e.GetVolumeInfo(name); err == nil {
			t.Fatalf("GetVolumeInfo accepted traversal name %q", name)
		}
		if _, err := e.CreateSnapshot(name, "snap"); err == nil {
			t.Fatalf("CreateSnapshot accepted traversal source %q", name)
		}
		if _, err := e.CreateSnapshot("src", name); err == nil {
			t.Fatalf("CreateSnapshot accepted traversal snapshot name %q", name)
		}
		if err := e.DeleteSnapshot(name); err == nil {
			t.Fatalf("DeleteSnapshot accepted traversal name %q", name)
		}
		// ListSnapshots("") is a valid "list all" filter, so only non-empty
		// names must be rejected there.
		if name != "" {
			if _, err := e.ListSnapshots(name); err == nil {
				t.Fatalf("ListSnapshots accepted traversal filter %q", name)
			}
		}
	}
	// Nothing may have been created inside or outside the engine root.
	entries, err := os.ReadDir(e.root)
	if err != nil {
		t.Fatalf("readdir root: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, ent := range entries {
			names = append(names, ent.Name())
		}
		t.Fatalf("traversal attempts created files: %v", names)
	}
}

func TestEngine_VolumeSnapshotLifecycle(t *testing.T) {
	root := t.TempDir()
	e := NewEngine(root)

	path, err := e.CreateVolume("data", 1<<20)
	if err != nil {
		t.Fatalf("create volume: %v", err)
	}
	if filepath.Dir(path) != root {
		t.Fatalf("volume created outside engine root: %s", path)
	}

	info, err := e.GetVolumeInfo("data")
	if err != nil {
		t.Fatalf("volume info: %v", err)
	}
	if info.SizeBytes != 1<<20 {
		t.Fatalf("volume size = %d, want %d", info.SizeBytes, uint64(1<<20))
	}
	if info.CreatedAt == "" {
		t.Fatalf("CreatedAt empty")
	}

	vols, err := e.ListVolumes()
	if err != nil || len(vols) != 1 || vols[0].Name != "data" {
		t.Fatalf("list volumes: err=%v len=%d", err, len(vols))
	}

	snapPath, err := e.CreateSnapshot("data", "s1")
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	if filepath.Dir(snapPath) != root {
		t.Fatalf("snapshot created outside engine root: %s", snapPath)
	}

	snaps, err := e.ListSnapshots("data")
	if err != nil || len(snaps) != 1 {
		t.Fatalf("list snapshots(data): err=%v len=%d", err, len(snaps))
	}
	if snaps[0].Name != "s1" || snaps[0].OriginVolume != "data" {
		t.Fatalf("snapshot record mismatch: %+v", snaps[0])
	}
	// empty filter lists all snapshots
	all, err := e.ListSnapshots("")
	if err != nil || len(all) != 1 {
		t.Fatalf("list snapshots(all): err=%v len=%d", err, len(all))
	}

	if err := e.DeleteSnapshot("s1"); err != nil {
		t.Fatalf("delete snapshot: %v", err)
	}
	if err := e.DeleteVolume("data"); err != nil {
		t.Fatalf("delete volume: %v", err)
	}
	vols2, err := e.ListVolumes()
	if err != nil || len(vols2) != 0 {
		t.Fatalf("after delete: err=%v len=%d", err, len(vols2))
	}
}
