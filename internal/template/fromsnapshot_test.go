package template

// fromsnapshot_test.go — snapshot promotion: flatten produces a standalone
// image, provenance is recorded, inspection fills size/hash.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"uml-container/internal/cow"
	"uml-container/internal/state"
)

// mkSnapshotTask builds a task dir with a base image + an overlay snapshot
// whose backing chain reaches into the base (the flatten path that matters).
func mkSnapshotTask(t *testing.T) (taskID, snapID, overlay string) {
	t.Helper()
	root := t.TempDir()
	state.RootDir = root
	taskID = "snaptest"
	cdir, err := state.ContainerDir(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Build a base volume + an overlay snapshot through the cow engine
	// (the same shapes the snapshot plane produces).
	eng := cow.NewEngine(root)
	if _, err := eng.CreateVolume("base", 1<<20); err != nil {
		t.Skipf("volume creation failed: %v", err)
	}
	var oerr error
	overlay, oerr = eng.CreateSnapshot("base", "snapov")
	if oerr != nil {
		t.Skipf("overlay creation failed: %v", oerr)
	}

	snapID = "snap-manual-1"
	snapDir := filepath.Join(cdir, "snapshots", snapID)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// event.json pointing at the overlay (the production layout).
	event := fmt.Sprintf(`{"id":%q,"task_id":%q,"disk_overlay":%q}`, snapID, taskID, overlay)
	if err := os.WriteFile(filepath.Join(snapDir, "event.json"), []byte(event), 0o644); err != nil {
		t.Fatal(err)
	}
	return taskID, snapID, overlay
}

func TestCreateFromSnapshotFlattens(t *testing.T) {
	taskID, snapID, overlay := mkSnapshotTask(t)
	storeRoot := t.TempDir()
	s := NewStore(storeRoot)

	rec, err := CreateFromSnapshot(context.Background(), s, taskID, snapID, "promoted")
	if err != nil {
		t.Fatalf("promotion failed: %v", err)
	}
	if rec.Status != "READY" || rec.Kind != "template" {
		t.Fatalf("record = %+v", rec)
	}
	if rec.ImageRef != fmt.Sprintf("snapshot:%s/%s", taskID, snapID) {
		t.Fatalf("provenance = %q", rec.ImageRef)
	}
	if rec.ImageSizeBytes != 1<<20 {
		t.Fatalf("size = %d, want %d", rec.ImageSizeBytes, 1<<20)
	}
	// The promoted image is EXACTLY the chain flatten (byte-for-byte the
	// direct ConvertToRaw of the same overlay) and carries no qcow2 magic.
	ref := filepath.Join(t.TempDir(), "ref.raw")
	if err := cow.ConvertToRaw(context.Background(), overlay, ref); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(rec.ImagePath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1<<20 || string(got) != string(want) {
		t.Fatalf("promotion output differs from the reference flatten (%d vs %d bytes)", len(got), len(want))
	}
	if len(got) >= 4 && string(got[:4]) == "QFI\x02" {
		t.Fatal("promoted image must be RAW, not qcow2")
	}
	// The hash matches the file.
	h := sha256.New()
	if _, err := h.Write(got); err != nil {
		t.Fatal(err)
	}
	if rec.ImageSHA256 != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("sha256 mismatch")
	}
	// Alias resolves.
	if got, err := s.GetByAlias("promoted"); err != nil || got.TemplateID != rec.TemplateID {
		t.Fatalf("alias lookup = %+v %v", got, err)
	}
}

func TestCreateFromSnapshotValidation(t *testing.T) {
	state.RootDir = t.TempDir()
	s := NewStore(t.TempDir())
	cases := []struct {
		name       string
		taskID     string
		snapshotID string
		wantErr    error
	}{
		// snapshot_id arrives from the request body: separators and
		// traversal fragments must never reach filepath.Join.
		{"path separator", "task", "a/b", ErrInvalidSnapshotID},
		{"backslash separator", "task", `a\b`, ErrInvalidSnapshotID},
		{"parent traversal", "task", "..", ErrInvalidSnapshotID},
		{"dot", "task", ".", ErrInvalidSnapshotID},
		{"nested traversal", "task", "../snap-1", ErrInvalidSnapshotID},
		{"traversal via event lookup", "task", "../../elsewhere", ErrInvalidSnapshotID},
		{"missing snapshot", "ghost", "snap-none", ErrSnapshotNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateFromSnapshot(context.Background(), s, tc.taskID, tc.snapshotID, "")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestInspectFillsStats(t *testing.T) {
	taskID, snapID, _ := mkSnapshotTask(t)
	s := NewStore(t.TempDir())
	rec, err := CreateFromSnapshot(context.Background(), s, taskID, snapID, "")
	if err != nil {
		t.Fatal(err)
	}
	// Wipe the stats and re-inspect: they must be recomputed.
	_ = s.Update(rec.TemplateID, func(r *Record) error {
		r.ImageSizeBytes = 0
		r.ImageSHA256 = ""
		return nil
	})
	got, err := Inspect(s, rec.TemplateID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ImageSizeBytes != 1<<20 || got.ImageSHA256 == "" {
		t.Fatalf("inspect did not refill stats: %+v", got)
	}
}

func TestSnapshotDiskFallbackScan(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "disk.qcow2"), []byte("qcow"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := snapshotDisk(dir)
	if err != nil || got != filepath.Join(dir, "disk.qcow2") {
		t.Fatalf("fallback scan = %q %v", got, err)
	}
	if _, err := snapshotDisk(t.TempDir()); err == nil {
		t.Fatal("empty dir must not resolve")
	}
}
