package template

// fromsnapshot.go — promote a task snapshot into a READY template.
//
// A snapshot's disk is an overlay whose backing chain reaches into the
// task's base image; a template must be a STANDALONE bootable image, so
// promotion flattens the chain (cow.ConvertToRaw — the pure-Go
// `qemu-img convert -O raw`) into the template store and records the
// provenance (ImageRef = snapshot:<task>/<snap>). The template is READY
// immediately: no build pipeline runs, the image already booted once.
//
// Inspection fills the size/hash fields on first use (and at promotion)
// so GET /inspect is cheap afterwards.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"uml-container/internal/cow"
	"uml-container/internal/state"
)

// ErrSnapshotNotFound marks a missing task/snapshot pair.
var ErrSnapshotNotFound = fmt.Errorf("template: snapshot not found")

// snapshotDisk resolves the snapshot's disk overlay path: from the
// persisted event record when possible, else the first image file in the
// snapshot directory.
func snapshotDisk(snapDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(snapDir, "event.json"))
	if err == nil {
		var ev struct {
			DiskOverlay string `json:"disk_overlay"`
		}
		if json.Unmarshal(raw, &ev) == nil && ev.DiskOverlay != "" {
			if _, err := os.Stat(ev.DiskOverlay); err == nil {
				return ev.DiskOverlay, nil
			}
		}
	}
	entries, err := os.ReadDir(snapDir)
	if err != nil {
		return "", ErrSnapshotNotFound
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch filepath.Ext(e.Name()) {
		case ".qcow2", ".img", ".raw":
			return filepath.Join(snapDir, e.Name()), nil
		}
	}
	return "", ErrSnapshotNotFound
}

// CreateFromSnapshot promotes taskID's snapshotID into a new READY
// template. The snapshot is left untouched (templates are independent
// copies).
func CreateFromSnapshot(s *Store, taskID, snapshotID, alias string) (*Record, error) {
	if taskID == "" {
		return nil, fmt.Errorf("template: task id required")
	}
	// Locate the snapshot directory (state layout: <container>/snapshots/<id>).
	cdir, err := state.ContainerDir(taskID)
	if err != nil {
		return nil, fmt.Errorf("template: task %s: %w", taskID, err)
	}
	snapDir := filepath.Join(cdir, "snapshots", snapshotID)
	disk, err := snapshotDisk(snapDir)
	if err != nil {
		return nil, fmt.Errorf("template: snapshot %s/%s: %w", taskID, snapshotID, err)
	}

	id := GenerateTemplateID()
	tplDir, err := s.dir(id)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		return nil, fmt.Errorf("template: create dir: %w", err)
	}
	dest := filepath.Join(tplDir, "image.raw")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := cow.ConvertToRaw(ctx, disk, dest); err != nil {
		_ = os.RemoveAll(tplDir)
		return nil, fmt.Errorf("template: flatten snapshot disk: %w", err)
	}

	rec := Record{
		TemplateID:  id,
		Alias:       alias,
		Kind:        "template",
		Status:      "READY",
		ImageRef:    fmt.Sprintf("snapshot:%s/%s", taskID, snapshotID),
		ImagePath:   dest,
		CreatedAt:   time.Now().UTC(),
	}
	if err := fillImageStats(&rec); err != nil {
		_ = os.RemoveAll(tplDir)
		return nil, err
	}
	if err := s.Create(rec); err != nil {
		_ = os.RemoveAll(tplDir)
		return nil, err
	}
	out := rec
	return &out, nil
}

// fillImageStats records the image's size and SHA-256 into the record.
func fillImageStats(rec *Record) error {
	if rec.ImagePath == "" {
		return nil
	}
	info, err := os.Stat(rec.ImagePath)
	if err != nil {
		return fmt.Errorf("template: image stat: %w", err)
	}
	rec.ImageSizeBytes = info.Size()
	f, err := os.Open(rec.ImagePath)
	if err != nil {
		return fmt.Errorf("template: image open: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("template: image hash: %w", err)
	}
	rec.ImageSHA256 = hex.EncodeToString(h.Sum(nil))
	return nil
}

// Inspect returns the record with image stats filled (computing and
// persisting them on first inspection).
func Inspect(s *Store, id string) (*Record, error) {
	rec, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if rec.ImageSizeBytes == 0 && rec.ImagePath != "" && rec.Status == "READY" {
		if err := fillImageStats(rec); err == nil {
			_ = s.Update(id, func(r *Record) error {
				r.ImageSizeBytes = rec.ImageSizeBytes
				r.ImageSHA256 = rec.ImageSHA256
				return nil
			})
		}
	}
	return rec, nil
}

// SnapshotIDs lists a task's snapshots (for the promotion API's callers).
func SnapshotIDs(taskID string) ([]string, error) {
	cdir, err := state.ContainerDir(taskID)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(cdir, "snapshots"))
	if err != nil {
		return nil, nil // no snapshots yet
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
