// Package cow — Engine abstraction (Cube parity: cubecow/src/engine/mod.rs).
//
// The original pure-Go qcow2 (qcow2.go) is the only backend today.
// Engine selects the backend at construction time via NewEngine, mirroring
// cubecow's crate::initialize(BackendKind). Future backends (e.g. reflink)
// implement the same trait.
package cow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Volume mirrors cubecow::Volume / Cubelet/pkg/cubecow.Volume.
type Volume struct {
	Name          string `json:"name"`
	SizeBytes     uint64 `json:"size_bytes"`
	DevicePath    string `json:"device_path"`
	SnapshotCount int    `json:"snapshot_count"`
	CreatedAt     string `json:"created_at"`
}

// Snapshot mirrors cubecow::Snapshot.
type Snapshot struct {
	Name         string `json:"name"`
	SizeBytes    uint64 `json:"size_bytes"`
	DevicePath   string `json:"device_path"`
	OriginVolume string `json:"origin_volume"`
	CreatedAt    string `json:"created_at"`
}

// Engine is the backend-agnostic trait (cf. cubecow/src/engine/mod.rs).
type Engine interface {
	CreateVolume(name string, sizeBytes uint64) (string, error)
	DeleteVolume(name string) error
	GetVolumeInfo(name string) (*Volume, error)
	ListVolumes() ([]Volume, error)
	CreateSnapshot(sourceName, snapshotName string) (string, error)
	DeleteSnapshot(snapshotName string) error
	ListSnapshots(volumeName string) ([]Snapshot, error)
}

// Qcow2Engine is the qcow2-file backend. Each volume is a standalone qcow2
// file at <root>/<name>.qcow2; snapshots are qcow2 overlays whose backing
// file is the source volume/snapshot (the host's qcow2 backing chain).
type Qcow2Engine struct {
	mu   sync.Mutex
	root string
}

// NewEngine creates the default (qcow2) engine at root. Root defaults to
// /var/lib/uml-container/cow when empty (overridable via PVM_COW_ROOT).
func NewEngine(root string) *Qcow2Engine {
	if root == "" {
		if v := os.Getenv("PVM_COW_ROOT"); v != "" {
			root = v
		} else {
			root = "/var/lib/uml-container/cow"
		}
	}
	return &Qcow2Engine{root: root}
}

func (e *Qcow2Engine) volumePath(name string) string {
	return filepath.Join(e.root, name+".qcow2")
}

func (e *Qcow2Engine) snapshotPath(name string) string {
	return filepath.Join(e.root, "snap-"+name+".qcow2")
}

// CreateVolume creates a standalone qcow2 volume of sizeBytes.
func (e *Qcow2Engine) CreateVolume(name string, sizeBytes uint64) (string, error) {
	if name == "" {
		return "", fmt.Errorf("cow: volume name required")
	}
	if sizeBytes == 0 {
		return "", fmt.Errorf("cow: volume size must be > 0")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := os.MkdirAll(e.root, 0755); err != nil {
		return "", err
	}
	path := e.volumePath(name)
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("cow: volume %q already exists", name)
	}
	if err := createQcow2(path, sizeBytes, "", "", defaultOverlayOpt); err != nil {
		return "", err
	}
	return path, nil
}

func (e *Qcow2Engine) DeleteVolume(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	path := e.volumePath(name)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cow: volume %q not found", name)
	}
	return os.Remove(path)
}

func (e *Qcow2Engine) GetVolumeInfo(name string) (*Volume, error) {
	path := e.volumePath(name)
	img, err := openGuestImage(path)
	if err != nil {
		return nil, fmt.Errorf("cow: volume %q not found: %w", name, err)
	}
	defer img.Close()
	st, _ := os.Stat(path)
	return &Volume{
		Name:       name,
		SizeBytes:  img.Size(),
		DevicePath: path,
		CreatedAt:  st.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
	}, nil
}

func (e *Qcow2Engine) ListVolumes() ([]Volume, error) {
	entries, err := os.ReadDir(e.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Volume
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".qcow2" {
			continue
		}
		// snapshots are "snap-*.qcow2"
		if len(ent.Name()) > 5 && ent.Name()[:5] == "snap-" {
			continue
		}
		name := ent.Name()[:len(ent.Name())-6]
		if v, err := e.GetVolumeInfo(name); err == nil {
			out = append(out, *v)
		}
	}
	return out, nil
}

func (e *Qcow2Engine) CreateSnapshot(sourceName, snapshotName string) (string, error) {
	if sourceName == "" || snapshotName == "" {
		return "", fmt.Errorf("cow: source and snapshot names required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	srcPath := e.volumePath(sourceName)
	if _, err := os.Stat(srcPath); err != nil {
		// also try as snapshot source
		srcPath = e.snapshotPath(sourceName)
		if _, err2 := os.Stat(srcPath); err2 != nil {
			return "", fmt.Errorf("cow: source %q not found", sourceName)
		}
	}
	dstPath := e.snapshotPath(snapshotName)
	if _, err := os.Stat(dstPath); err == nil {
		return "", fmt.Errorf("cow: snapshot %q already exists", snapshotName)
	}
	if err := os.MkdirAll(e.root, 0755); err != nil {
		return "", err
	}
	if err := CreateOverlay(context.Background(), srcPath, dstPath); err != nil {
		return "", err
	}
	return dstPath, nil
}

func (e *Qcow2Engine) DeleteSnapshot(snapshotName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	path := e.snapshotPath(snapshotName)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cow: snapshot %q not found", snapshotName)
	}
	return os.Remove(path)
}

func (e *Qcow2Engine) ListSnapshots(volumeName string) ([]Snapshot, error) {
	// PVM snapshots are global (snap-*.qcow2) and carry backing chain;
	// filter by resolving backing.
	entries, err := os.ReadDir(e.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Snapshot
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".qcow2" || len(ent.Name()) <= 5 || ent.Name()[:5] != "snap-" {
			continue
		}
		name := ent.Name()[5 : len(ent.Name())-6]
		path := filepath.Join(e.root, ent.Name())
		img, err := openGuestImage(path)
		if err != nil {
			continue
		}
		size := img.Size()
		img.Close()
		st, _ := os.Stat(path)
		origin := volumeName // best-effort; qcow2 header carries backing name
		if q, err := openGuestImage(path); err == nil {
			if qi, ok := q.(*qcow2Image); ok && qi.backingName != "" {
				origin = filepath.Base(qi.backingName)
				if ext := filepath.Ext(origin); ext == ".qcow2" {
					origin = origin[:len(origin)-len(ext)]
					if len(origin) > 5 && origin[:5] == "snap-" {
						origin = origin[5:]
					}
				}
			}
			q.Close()
		}
		if volumeName != "" && origin != volumeName {
			continue
		}
		out = append(out, Snapshot{
			Name:         name,
			SizeBytes:    size,
			DevicePath:   path,
			OriginVolume: origin,
			CreatedAt:    st.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	return out, nil
}
