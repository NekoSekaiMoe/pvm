package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"uml-container/internal/cow"
	"uml-container/internal/state"
)

var cloneMu sync.Mutex

// Clone performs an instant Copy-on-Write clone of an existing container/task.
// It branches the disk overlay in O(1) time and initializes a clean, isolated
// state for the new container ID.
func Clone(sourceID, newID string) error {
	if !validContainerID.MatchString(sourceID) {
		return fmt.Errorf("snapshot: invalid source ID %q", sourceID)
	}
	if !validContainerID.MatchString(newID) {
		return fmt.Errorf("snapshot: invalid target ID %q", newID)
	}
	if sourceID == newID {
		return fmt.Errorf("snapshot: source and target ID cannot be identical (%q)", sourceID)
	}

	cloneMu.Lock()
	defer cloneMu.Unlock()

	srcDir, err := state.ContainerDir(sourceID)
	if err != nil {
		return err
	}
	dstDir, err := state.ContainerDir(newID)
	if err != nil {
		return err
	}

	if _, err := os.Stat(srcDir); err != nil {
		return fmt.Errorf("snapshot: source container %q not found: %w", sourceID, err)
	}
	if _, err := os.Stat(dstDir); err == nil {
		return fmt.Errorf("snapshot: target container %q already exists", newID)
	}

	// Atomically reserve destination directory
	if err := os.Mkdir(dstDir, 0755); err != nil {
		return fmt.Errorf("snapshot: failed to create target directory %q: %w", dstDir, err)
	}

	cloneOk := false
	defer func() {
		if !cloneOk {
			os.RemoveAll(dstDir)
		}
	}()

	// 1. Branch storage layer via Copy-on-Write
	srcOverlay := filepath.Join(srcDir, "overlay.qcow2")
	dstOverlay := filepath.Join(dstDir, "overlay.qcow2")
	srcRootfs := filepath.Join(srcDir, "rootfs.img")

	if _, err := os.Stat(srcOverlay); err == nil {
		// Create a new overlay with srcOverlay as its backing image (zero-copy instant branch)
		if err := cow.CreateOverlay(nil, srcOverlay, dstOverlay); err != nil {
			// Fallback: copy overlay file directly
			if data, rerr := os.ReadFile(srcOverlay); rerr == nil {
				_ = os.WriteFile(dstOverlay, data, 0644)
			} else {
				return fmt.Errorf("snapshot: failed to clone overlay: %w", err)
			}
		}
	} else if _, err := os.Stat(srcRootfs); err == nil {
		// Base rootfs exists; create an overlay backed by the base rootfs
		if err := cow.CreateOverlay(nil, srcRootfs, dstOverlay); err != nil {
			// Fallback: copy rootfs
			if data, rerr := os.ReadFile(srcRootfs); rerr == nil {
				_ = os.WriteFile(filepath.Join(dstDir, "rootfs.img"), data, 0644)
			}
		}
	}

	// 2. Clone and derive task state
	st, err := state.LoadState(sourceID)
	if err != nil {
		// If source state is missing, create a minimal initial state
		st = &state.ContainerState{
			ID:     sourceID,
			Name:   sourceID,
			Status: state.StatusReady,
		}
	}

	now := time.Now().UTC()
	newState := &state.ContainerState{
		ID:          newID,
		Name:        newID,
		Tenant:      st.Tenant,
		Caller:      st.Caller,
		Status:      state.StatusReady,
		PID:         0,
		StartedAt:   now,
		SpecFP:      st.SpecFP,
		IdleTimeout: st.IdleTimeout,
		AutoResume:  st.AutoResume,
		Transitions: []state.Transition{
			{
				From:   state.StatusPending,
				To:     state.StatusReady,
				Actor:  state.ActorSystem,
				Reason: fmt.Sprintf("instant clone from %s", sourceID),
				At:     now,
			},
		},
	}

	if err := state.SaveState(newID, newState); err != nil {
		return fmt.Errorf("snapshot: failed to persist cloned state: %w", err)
	}

	cloneOk = true
	return nil
}
