// Package cow — the qcow2 volume/snapshot Engine abstraction.
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
	"regexp"
	"strings"
	"sync"
)

// nameRe constrains volume and snapshot names so they cannot traverse out of
// the engine root (mirrors internal/volume volumeIDRe; "/" and "." are
// rejected, defeating "../" and absolute-path escapes in filepath.Join).
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func validateName(kind, name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("cow: %w %s name %q (must match %s)", ErrInvalid, kind, name, nameRe.String())
	}
	return nil
}

// Volume is one engine-managed qcow2 volume record.
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
	CloneVolume(sourceVolume, newVolume string) (string, error)
	RollbackVolume(volumeName, snapshotName string) error
}

// Qcow2Engine is the qcow2-file backend. Each volume is a standalone qcow2
// file at <root>/<name>.qcow2; snapshots are qcow2 overlays whose backing
// file is the source volume/snapshot (the host's qcow2 backing chain).
type Qcow2Engine struct {
	mu   sync.Mutex
	root string
}

// NewEngine creates the default (qcow2) engine at root. Root defaults to
// /var/lib/uml-container/cow when empty (overridable via PVM_COW_ROOT);
// see ResolveRoot.
func NewEngine(root string) *Qcow2Engine {
	return &Qcow2Engine{root: ResolveRoot(root)}
}

// ResolveRoot resolves the engine storage root: a non-empty root wins,
// otherwise PVM_COW_ROOT, else /var/lib/uml-container/cow. Callers that need
// to derive paths next to the engine's volumes and snapshots (e.g. API
// handlers stat-ing <root>/<id>.qcow2 before calling the engine) must use
// this instead of the raw environment variable, or their paths silently
// diverge from the engine's whenever the variable is empty.
func ResolveRoot(root string) string {
	if root == "" {
		if v := os.Getenv("PVM_COW_ROOT"); v != "" {
			root = v
		} else {
			root = "/var/lib/uml-container/cow"
		}
	}
	return root
}

func (e *Qcow2Engine) volumePath(name string) string {
	return filepath.Join(e.root, name+".qcow2")
}

func (e *Qcow2Engine) snapshotPath(name string) string {
	return filepath.Join(e.root, "snap-"+name+".qcow2")
}

// CreateVolume creates a standalone qcow2 volume of sizeBytes.
func (e *Qcow2Engine) CreateVolume(name string, sizeBytes uint64) (string, error) {
	if err := validateName("volume", name); err != nil {
		return "", err
	}
	// The "snap-" prefix is reserved for snapshot files: volumePath(name) is
	// <root>/<name>.qcow2 while snapshotPath(name) is <root>/snap-<name>.qcow2,
	// so a volume named "snap-x" would collide with snapshot "x"'s file and
	// DeleteSnapshot("x") could delete the volume. Snapshot names are
	// unaffected: snapshot "snap-x" maps to snap-snap-x.qcow2, which cannot
	// collide with any volume name.
	if strings.HasPrefix(name, "snap-") {
		return "", fmt.Errorf("cow: volume name %q must not start with %q (reserved for snapshots): %w", name, "snap-", ErrInvalid)
	}
	if sizeBytes == 0 {
		return "", fmt.Errorf("cow: volume size must be > 0: %w", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := os.MkdirAll(e.root, 0755); err != nil {
		return "", err
	}
	path := e.volumePath(name)
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("cow: volume %q %w", name, ErrExists)
	}
	if err := createQcow2(path, sizeBytes, "", "", defaultOverlayOpt); err != nil {
		return "", err
	}
	return path, nil
}

func (e *Qcow2Engine) DeleteVolume(name string) error {
	if err := validateName("volume", name); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	path := e.volumePath(name)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cow: volume %q %w", name, ErrNotFound)
	}
	hasRef, refName, err := e.hasBackingReference(path)
	if err != nil {
		// Fail closed: without a successful reference scan we cannot know
		// whether deleting would orphan live dependents.
		return fmt.Errorf("cow: %w of volume %q: %w", ErrRefScan, name, err)
	}
	if hasRef {
		return fmt.Errorf("cow: cannot delete volume %q: %w %q", name, ErrReferenced, refName)
	}
	return os.Remove(path)
}

func (e *Qcow2Engine) GetVolumeInfo(name string) (*Volume, error) {
	if err := validateName("volume", name); err != nil {
		return nil, err
	}
	path := e.volumePath(name)
	img, err := openGuestImage(path)
	if err != nil {
		return nil, fmt.Errorf("cow: volume %q %w: %w", name, ErrNotFound, err)
	}
	defer img.Close()
	// The file may be deleted concurrently (GetVolumeInfo runs without the
	// engine lock; DeleteVolume removes it). A nil st must not panic.
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cow: stat volume %q: %w", name, err)
	}
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
	if err := validateName("source", sourceName); err != nil {
		return "", err
	}
	if err := validateName("snapshot", snapshotName); err != nil {
		return "", err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	srcPath := e.volumePath(sourceName)
	if _, err := os.Stat(srcPath); err != nil {
		// also try as snapshot source
		srcPath = e.snapshotPath(sourceName)
		if _, err2 := os.Stat(srcPath); err2 != nil {
			return "", fmt.Errorf("cow: source %q %w", sourceName, ErrNotFound)
		}
	}
	dstPath := e.snapshotPath(snapshotName)
	if _, err := os.Stat(dstPath); err == nil {
		return "", fmt.Errorf("cow: snapshot %q %w", snapshotName, ErrExists)
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
	if err := validateName("snapshot", snapshotName); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	path := e.snapshotPath(snapshotName)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cow: snapshot %q %w", snapshotName, ErrNotFound)
	}
	hasRef, refName, err := e.hasBackingReference(path)
	if err != nil {
		// Fail closed, mirroring DeleteVolume: an unreadable root must not
		// degrade into deleting a snapshot live dependents still need.
		return fmt.Errorf("cow: %w of snapshot %q: %w", ErrRefScan, snapshotName, err)
	}
	if hasRef {
		return fmt.Errorf("cow: cannot delete snapshot %q: %w %q", snapshotName, ErrReferenced, refName)
	}
	return os.Remove(path)
}

func (e *Qcow2Engine) ListSnapshots(volumeName string) ([]Snapshot, error) {
	// volumeName is an optional filter (empty lists all).
	if volumeName != "" {
		if err := validateName("volume", volumeName); err != nil {
			return nil, err
		}
	}
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
		// Open once: size AND backing chain must come from the same file state.
		img, err := openGuestImage(path)
		if err != nil {
			continue
		}
		size := img.Size()
		// Walk the qcow2 backing chain to the root origin: for snapshot-of-
		// snapshot chains (vol -> snapA -> snapB) the direct backing file is
		// another snapshot, so keep following until the backing name stops
		// resolving to a snapshot (best-effort). When the chain cannot be
		// resolved — a missing intermediate snapshot, a non-qcow2 hop, or a
		// cycle — origin stays EMPTY rather than falling back to volumeName:
		// self-attributing would report the snapshot as its own origin (and,
		// when filtering, wrongly claim it for that volume), while "" marks
		// the origin as unknown so callers cannot mis-route it.
		origin := "" // stays empty unless the walk resolves a root volume
		if qi, ok := img.(*qcow2Image); ok && qi.backingName != "" {
			backing := qi.backingName
			for hop := 0; hop < 64 && backing != ""; hop++ {
				base := filepath.Base(backing)
				if ext := filepath.Ext(base); ext == ".qcow2" {
					base = base[:len(base)-len(ext)]
				}
				if len(base) > 5 && base[:5] == "snap-" {
					// backing is another snapshot; follow ITS backing file.
					next, oerr := openGuestImage(filepath.Join(e.root, filepath.Base(backing)))
					if oerr != nil {
						break // unresolvable link: origin stays unknown
					}
					nq, ok2 := next.(*qcow2Image)
					if !ok2 || nq.backingName == "" {
						next.Close()
						break
					}
					backing = nq.backingName
					next.Close()
					continue
				}
				origin = base // first non-snapshot backing is the root volume
				break
			}
		}
		img.Close()
		// Best-effort created-at: the file may vanish between open and stat
		// (concurrent DeleteSnapshot); use a zero timestamp instead of panicking.
		var created string
		if st, err := os.Stat(path); err == nil {
			created = st.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		if volumeName != "" && origin != volumeName {
			continue
		}
		out = append(out, Snapshot{
			Name:         name,
			SizeBytes:    size,
			DevicePath:   path,
			OriginVolume: origin,
			CreatedAt:    created,
		})
	}
	return out, nil
}

// CloneVolume creates a new volume instantly via Copy-on-Write branching from an existing volume or snapshot.
func (e *Qcow2Engine) CloneVolume(sourceVolume, newVolume string) (string, error) {
	if err := validateName("source", sourceVolume); err != nil {
		return "", err
	}
	if err := validateName("volume", newVolume); err != nil {
		return "", err
	}
	if strings.HasPrefix(newVolume, "snap-") {
		return "", fmt.Errorf("cow: volume name %q must not start with %q (reserved for snapshots): %w", newVolume, "snap-", ErrInvalid)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	srcPath := e.volumePath(sourceVolume)
	if _, err := os.Stat(srcPath); err != nil {
		srcPath = e.snapshotPath(sourceVolume)
		if _, err2 := os.Stat(srcPath); err2 != nil {
			return "", fmt.Errorf("cow: source volume or snapshot %q %w", sourceVolume, ErrNotFound)
		}
	}

	dstPath := e.volumePath(newVolume)
	if _, err := os.Stat(dstPath); err == nil {
		return "", fmt.Errorf("cow: target volume %q %w", newVolume, ErrExists)
	}

	if err := os.MkdirAll(e.root, 0755); err != nil {
		return "", err
	}

	if err := CreateOverlay(context.Background(), srcPath, dstPath); err != nil {
		return "", err
	}
	return dstPath, nil
}

// RollbackVolume resets a volume to a previous snapshot state.
func (e *Qcow2Engine) RollbackVolume(volumeName, snapshotName string) error {
	if err := validateName("volume", volumeName); err != nil {
		return err
	}
	if err := validateName("snapshot", snapshotName); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	volPath := e.volumePath(volumeName)
	if _, err := os.Stat(volPath); err != nil {
		return fmt.Errorf("cow: volume %q %w", volumeName, ErrNotFound)
	}

	snapPath := e.snapshotPath(snapshotName)
	if _, err := os.Stat(snapPath); err != nil {
		return fmt.Errorf("cow: snapshot %q %w", snapshotName, ErrNotFound)
	}

	// The rollback REPLACES volPath in place (convert + rename). Any other
	// volume or snapshot whose backing chain reaches volPath — clones,\t// dependent snapshots — would silently observe the rolled-back content.
	// The rollback TARGET snapshot itself is the one permitted reference:
	// it is the source of the restore, not a victim of it.
	hasRef, refName, err := e.hasBackingReferenceExcluding(volPath, snapPath)
	if err != nil {
		return fmt.Errorf("cow: %w of volume %q: %w", ErrRefScan, volumeName, err)
	}
	if hasRef {
		return fmt.Errorf("cow: cannot rollback volume %q: %q %w (delete or roll back the dependent first)", volumeName, refName, ErrBackedBy)
	}

	tmpPath := filepath.Join(e.root, ".tmp-rb-"+volumeName+".qcow2")
	_ = os.Remove(tmpPath)
	if err := ConvertToQcow2(context.Background(), snapPath, tmpPath, ConvertDefaultOpt); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("cow: create rollback overlay: %w", err)
	}

	if err := os.Rename(tmpPath, volPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// hasBackingReference reports whether any existing volume or snapshot has a
// backing file referencing targetPath.
func (e *Qcow2Engine) hasBackingReference(targetPath string) (bool, string, error) {
	return e.hasBackingReferenceExcluding(targetPath, "")
}

// hasBackingReferenceExcluding reports whether any existing volume or
// snapshot OTHER than excludePath has a backing file referencing targetPath.
// Every candidate is scanned (the match does not short-circuit on the first
// hit) so the excluded file can never mask another dependent that also
// references the target.
func (e *Qcow2Engine) hasBackingReferenceExcluding(targetPath, excludePath string) (bool, string, error) {
	entries, err := os.ReadDir(e.root)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "", nil
		}
		return false, "", err
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		absTarget = targetPath
	}
	absExclude := ""
	if excludePath != "" {
		if absExclude, err = filepath.Abs(excludePath); err != nil {
			absExclude = excludePath
		}
	}
	targetBase := filepath.Base(targetPath)
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".qcow2" {
			continue
		}
		p := filepath.Join(e.root, ent.Name())
		// Fall back to the ORIGINAL path when Abs fails, mirroring the
		// absTarget/absExclude handling above: on resolution failure the
		// skip checks must still compare raw paths, or the target file and
		// the excluded snapshot would be scanned as mere candidates.
		absP := p
		if ap, aerr := filepath.Abs(p); aerr == nil {
			absP = ap
		}
		if absP == absTarget || p == targetPath {
			continue
		}
		if absExclude != "" && (absP == absExclude || p == excludePath) {
			continue
		}
		img, err := openGuestImage(p)
		if err != nil {
			continue
		}
		qi, ok := img.(*qcow2Image)
		if !ok || qi.backingName == "" {
			img.Close()
			continue
		}
		ref := false
		if qi.backingAbs == absTarget || qi.backingAbs == targetPath {
			ref = true
		} else if qi.backingName == targetBase || filepath.Base(qi.backingName) == targetBase {
			ref = true
		}
		img.Close()
		if ref {
			return true, ent.Name(), nil
		}
	}
	return false, "", nil
}
