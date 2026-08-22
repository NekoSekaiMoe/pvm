package snapshot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"uml-container/internal/state"
)

// Clone→parent reference tracking.
//
// An instant clone's overlay records an ABSOLUTE backing path into the
// source container's directory (cow.CreateOverlay resolves the backing to
// absolute before writing it into the qcow2 header), and the copyFile
// fallback byte-copies that same reference. Removing the source container
// directory would therefore break every clone's backing chain. These
// helpers record the dependency so deletion can be vetoed while clones
// still branch from a container, and unrecord it when a clone goes away.

const (
	// cloneRefsDir lives inside the PARENT's container dir; each file named
	// <clone-id> marks one live clone whose backing chain reaches into this
	// directory.
	cloneRefsDir = ".clones"
	// cloneParentFile lives inside the CLONE's dir and names the parent it
	// branches from, so deleting the clone can drop its marker from the
	// parent's cloneRefsDir.
	cloneParentFile = "clone-of"
)

// ErrHasClones reports that a container's disk files are the live backing
// of one or more instant clones; deleting the container would corrupt the
// clones' backing chains.
var ErrHasClones = errors.New("snapshot: container is branched-from by live clones")

// registerCloneRef records that newID's storage branches from sourceID's.
// Must only be called after the clone's storage was actually created —
// a marker without a real backing dependency would veto the parent's
// deletion forever.
func registerCloneRef(sourceID, newID string) error {
	srcDir, err := state.ContainerDir(sourceID)
	if err != nil {
		return err
	}
	refs := filepath.Join(srcDir, cloneRefsDir)
	if err := os.MkdirAll(refs, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(refs, newID), nil, 0644)
}

// unregisterCloneRef best-effort removes newID's marker from sourceID.
// Best-effort on purpose: a stale marker only delays the parent's deletion
// until manually cleaned, whereas failing hard here could block the clone's
// own cleanup path.
func unregisterCloneRef(sourceID, newID string) {
	srcDir, err := state.ContainerDir(sourceID)
	if err != nil {
		return
	}
	_ = os.Remove(filepath.Join(srcDir, cloneRefsDir, newID))
}

// ClonesOf returns the ids of containers whose storage branches from id's.
// A container with no cloneRefsDir (never cloned from) yields nil, nil.
func ClonesOf(id string) ([]string, error) {
	dir, err := state.ContainerDir(id)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, cloneRefsDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, ent := range entries {
		if ent.IsDir() || !validContainerID.MatchString(ent.Name()) {
			continue
		}
		out = append(out, ent.Name())
	}
	return out, nil
}

// PrepareDelete guards container-directory removal:
//
//  1. It refuses (wrapping ErrHasClones) while live clones still branch
//     from this container — deleting it would break their backing chains.
//  2. It drops this container's own marker from ITS parent (recorded when
//     this container is itself a clone), so the parent becomes deletable
//     again.
//
// Callers must invoke this before os.RemoveAll of the container dir and
// abort on error.
func PrepareDelete(id string) error {
	dir, err := state.ContainerDir(id)
	if err != nil {
		return err
	}
	clones, err := ClonesOf(id)
	if err != nil {
		// Fail closed like the cow engine's reference scan: an unreadable
		// refs dir must not degrade into deleting a live backing parent.
		return fmt.Errorf("snapshot: scan clones of %q: %w", id, err)
	}
	if len(clones) > 0 {
		return fmt.Errorf("%w: %q <- [%s] (delete the clones first)", ErrHasClones, id, strings.Join(clones, ", "))
	}
	// Not a parent of live clones: release OUR claim on our own parent, if any.
	if data, rerr := os.ReadFile(filepath.Join(dir, cloneParentFile)); rerr == nil {
		if parent := strings.TrimSpace(string(data)); parent != "" && parent != id {
			unregisterCloneRef(parent, id)
		}
	}
	return nil
}
