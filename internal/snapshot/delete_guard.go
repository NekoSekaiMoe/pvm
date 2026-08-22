package snapshot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"uml-container/internal/cow"
	"uml-container/internal/state"
)

// ErrSnapshotInUse reports that an event snapshot's overlay is still part
// of a live backing chain — the container's active overlay, one of its
// clones' (transitively), or a sibling snapshot's — so deleting the
// snapshot would break that chain at the next read-through.
var ErrSnapshotInUse = errors.New("snapshot: event snapshot is in use by a live backing chain")

// maxChainHops bounds the backing-chain walk per candidate overlay
// (mirrors ListSnapshots' chain-walk bound).
const maxChainHops = 64

// PrepareDeleteEventSnapshot guards deletion of one event snapshot: it
// vetoes (wrapping ErrSnapshotInUse) while any live overlay still reaches
// the snapshot's overlay through its backing chain. Rollback flattens the
// restored overlay into a standalone image (cow.ConvertToQcow2), so a
// completed rollback leaves NO reference and the snapshot stays freely
// deletable; this guard covers chains created by the pre-flattening
// rollback (whose branch step produced live → snap cycles and plain
// dependencies alike). Callers must invoke it before os.RemoveAll of the
// snapshot dir and abort on error.
func PrepareDeleteEventSnapshot(taskID, snapshotID string) error {
	if !validContainerID.MatchString(taskID) {
		return fmt.Errorf("snapshot: invalid task id %q", taskID)
	}
	if !validContainerID.MatchString(snapshotID) {
		return fmt.Errorf("snapshot: invalid snapshot id %q", snapshotID)
	}
	snapDir, err := snapshotsDir(taskID)
	if err != nil {
		return err
	}
	target := filepath.Join(snapDir, snapshotID, "overlay.qcow2")
	if _, err := os.Stat(target); err != nil {
		// No overlay in this snapshot dir → no backing chain can reach it.
		return nil
	}
	target = resolveChainPath(target)
	for _, dep := range dependentOverlays(taskID, target) {
		hop := dep
		for i := 0; i < maxChainHops; i++ {
			next, berr := cow.BackingOf(hop)
			if berr != nil {
				// Fail closed like the cow engine's reference scan: an
				// unreadable chain cannot prove the snapshot unreferenced.
				return fmt.Errorf("%w: scan backing chain of %s: %v", ErrSnapshotInUse, dep, berr)
			}
			if next == "" {
				break
			}
			if next == target {
				return fmt.Errorf("%w: %s reaches snapshot %q of %s through its backing chain (flatten or roll back the dependent first)", ErrSnapshotInUse, dep, snapshotID, taskID)
			}
			hop = next
		}
	}
	return nil
}

// resolveChainPath resolves p the way cow resolves backing paths
// (symlinks first, absolute as fallback) so both sides of the comparison
// carry the same normalization.
func resolveChainPath(p string) string {
	if rp, err := filepath.EvalSymlinks(p); err == nil {
		return rp
	}
	if ap, err := filepath.Abs(p); err == nil {
		return filepath.Clean(ap)
	}
	return filepath.Clean(p)
}

// dependentOverlays collects every overlay whose backing chain may reach
// into taskID's snapshot storage: the task's own live overlay, its sibling
// event snapshots' overlays, and — transitively through the clone markers —
// every clone's live overlay. The resolved target itself is excluded.
func dependentOverlays(taskID, target string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(dir string) {
		p := filepath.Join(dir, "overlay.qcow2")
		rp := resolveChainPath(p)
		if seen[rp] || rp == target {
			return
		}
		seen[rp] = true
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	dir, err := state.ContainerDir(taskID)
	if err != nil {
		return nil
	}
	add(dir)
	if snapDir, serr := snapshotsDir(taskID); serr == nil {
		if ents, rerr := os.ReadDir(snapDir); rerr == nil {
			for _, ent := range ents {
				if ent.IsDir() {
					add(filepath.Join(snapDir, ent.Name()))
				}
			}
		}
	}
	// Clones (transitively): a clone's overlay branches from the parent's
	// live overlay, so its chain reaches whatever the parent's live overlay
	// reaches — even one created before a later rollback replaced it.
	frontier := []string{taskID}
	visited := map[string]bool{taskID: true}
	for len(frontier) > 0 {
		cur := frontier[0]
		frontier = frontier[1:]
		clones, cerr := ClonesOf(cur)
		if cerr != nil {
			continue
		}
		for _, c := range clones {
			if visited[c] {
				continue
			}
			visited[c] = true
			if cd, derr := state.ContainerDir(c); derr == nil {
				add(cd)
				frontier = append(frontier, c)
			}
		}
	}
	return out
}
