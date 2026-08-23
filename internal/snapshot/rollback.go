package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"uml-container/internal/cow"
	"uml-container/internal/state"
)

var rollbackMu sync.Mutex

// ErrSpecMismatch is returned by Rollback when the task's CURRENT TaskSpec
// fingerprint differs from the one recorded alongside the snapshot. Rolling
// back would pair an old disk with a new configuration — the disk-edition
// analog of CubeShim's start_vm config guard. Callers may bypass it only by
// passing force=true.
var ErrSpecMismatch = errors.New("snapshot: spec fingerprint mismatch")

// Rollback restores a container's filesystem state and FSM state back to a
// specified historical EventSnapshot, refusing on spec mismatch.
func Rollback(taskID, snapshotID string) error {
	return RollbackWithForce(taskID, snapshotID, false)
}

// RollbackWithForce is Rollback with an explicit override for the spec
// alignment guard.
func RollbackWithForce(taskID, snapshotID string, force bool) error {
	if !validContainerID.MatchString(taskID) {
		return fmt.Errorf("snapshot: invalid task id %q", taskID)
	}
	if !validContainerID.MatchString(snapshotID) {
		return fmt.Errorf("snapshot: invalid snapshot id %q", snapshotID)
	}

	rollbackMu.Lock()
	defer rollbackMu.Unlock()

	dir, err := state.ContainerDir(taskID)
	if err != nil {
		return err
	}
	snapDir, err := snapshotsDir(taskID)
	if err != nil {
		return err
	}

	targetSnapDir := filepath.Join(snapDir, snapshotID)
	if _, err := os.Stat(targetSnapDir); err != nil {
		return fmt.Errorf("snapshot: snapshot %q not found for %s: %w", snapshotID, taskID, err)
	}

	// 1. Read snapshot metadata
	metaPath := filepath.Join(targetSnapDir, "snapshot.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("snapshot: failed to read snapshot metadata: %w", err)
	}
	var snap EventSnapshot
	if err := json.Unmarshal(metaData, &snap); err != nil {
		return fmt.Errorf("snapshot: failed to parse snapshot metadata: %w", err)
	}

	// Spec alignment guard (CubeShim start_vm pattern, disk edition): refuse
	// to roll a task whose current spec fingerprint differs from the one
	// recorded in the snapshot's state copy — "old snapshot + new config"
	// silently misconfigures the restored task. Runs BEFORE any mutation, so
	// a refusal leaves both disk and state untouched. Legacy containers whose
	// state copy parses cleanly but records no fingerprint skip the check.
	//
	// A state copy that cannot be READ or PARSED is NOT legacy: silently
	// treating it as "no fingerprint" would let a corrupt snapshot bypass the
	// guard and roll the disk back underneath a mismatched spec. Fail closed
	// unless the caller explicitly forces the rollback.
	snapStateBytes, snapStateErr := os.ReadFile(filepath.Join(targetSnapDir, "state.json"))
	snapSpecFP := ""
	switch {
	case snapStateErr != nil:
		if !force {
			return fmt.Errorf("snapshot: failed to read snapshot state copy: %w (retry with force)", snapStateErr)
		}
	default:
		var probe state.ContainerState
		if err := json.Unmarshal(snapStateBytes, &probe); err != nil {
			if !force {
				return fmt.Errorf("snapshot: failed to parse snapshot state copy: %w (retry with force)", err)
			}
		} else {
			// Legacy snapshots (predating SpecFP) parse fine but record an
			// empty fingerprint — only this case skips the guard below.
			snapSpecFP = probe.SpecFP
		}
	}
	currentState, _ := state.LoadState(taskID)
	if !force && snapSpecFP != "" && currentState != nil && currentState.SpecFP != "" && snapSpecFP != currentState.SpecFP {
		return fmt.Errorf("%w: snapshot spec %q != current spec %q (retry with force)", ErrSpecMismatch, snapSpecFP, currentState.SpecFP)
	}

	// 2. Restore disk overlay if present in snapshot
	snapOverlay := filepath.Join(targetSnapDir, "overlay.qcow2")
	currOverlay := filepath.Join(dir, "overlay.qcow2")
	if _, err := os.Stat(snapOverlay); err == nil {
		tmpOverlay := filepath.Join(dir, ".tmp-rb-overlay.qcow2")
		_ = os.Remove(tmpOverlay)
		// Flatten the snapshot into a STANDALONE image (mirrors
		// cow.RollbackVolume's convert+rename): the restored overlay must NOT
		// keep backing into the snapshot file under <dir>/snapshots/ —
		// deleting that event snapshot later would break the live chain.
		// Branching is NOT a fallback here: the snapshot's own backing IS the
		// live overlay path, so an overlay branched from the snapshot and
		// renamed over the live file creates a reference CYCLE (live → snap
		// → live) — exactly the pre-flattening behavior, which left the disk
		// unopenable after every rollback (the copyFile fallback was the same
		// class of bug: a self-referential overlay). If conversion fails,
		// abort with the disk untouched.
		if err := cow.ConvertToQcow2(context.Background(), snapOverlay, tmpOverlay, cow.ConvertDefaultOpt); err != nil {
			_ = os.Remove(tmpOverlay)
			return fmt.Errorf("snapshot: failed to restore overlay: %w", err)
		}
		if err := os.Rename(tmpOverlay, currOverlay); err != nil {
			_ = os.Remove(tmpOverlay)
			return fmt.Errorf("snapshot: failed to replace overlay: %w", err)
		}
	}

	// 3. Restore state machine (currentState was loaded pre-mutation by the
	// spec guard; the overlay restore above does not touch state.json).
	fromStatus := state.StatusRunning
	if currentState != nil {
		fromStatus = currentState.Status
	}

	snapStatePath := filepath.Join(targetSnapDir, "state.json")
	targetState := &state.ContainerState{}
	stateLoaded := false
	if stateBytes, err := os.ReadFile(snapStatePath); err == nil {
		if err := json.Unmarshal(stateBytes, targetState); err == nil {
			stateLoaded = true
		}
	}
	if !stateLoaded && currentState != nil {
		targetState = &state.ContainerState{
			ID:          currentState.ID,
			Name:        currentState.Name,
			Tenant:      currentState.Tenant,
			Caller:      currentState.Caller,
			Status:      currentState.Status,
			StartedAt:   currentState.StartedAt,
			SpecFP:      currentState.SpecFP,
			IdleTimeout: currentState.IdleTimeout,
			AutoResume:  currentState.AutoResume,
			Retries:     currentState.Retries,
			Deadline:    currentState.Deadline,
			Transitions: append([]state.Transition(nil), currentState.Transitions...),
		}
	}

	targetStatus := state.Status(snap.StateStatus)
	if targetStatus == "" {
		targetStatus = targetState.Status
	}
	if targetStatus == "" {
		targetStatus = state.StatusReady
	}

	now := time.Now().UTC()
	targetState.ID = taskID
	targetState.Name = taskID
	targetState.Status = targetStatus
	targetState.PID = 0 // process is stopped/reset after rollback

	// Record rollback in the transition log
	rollbackTrans := state.Transition{
		From:   fromStatus,
		To:     targetStatus,
		Actor:  state.ActorHuman,
		Reason: fmt.Sprintf("rollback to snapshot %s (event=%s)", snapshotID, snap.EventID),
		At:     now,
	}
	targetState.Transitions = append(targetState.Transitions, rollbackTrans)

	if err := state.SaveState(taskID, targetState); err != nil {
		return fmt.Errorf("snapshot: failed to persist rolled-back state: %w", err)
	}

	return nil
}
