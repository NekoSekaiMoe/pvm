package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"uml-container/internal/cow"
	"uml-container/internal/state"
)

var rollbackMu sync.Mutex

// Rollback restores a container's filesystem state and FSM state back to a
// specified historical EventSnapshot.
func Rollback(taskID, snapshotID string) error {
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

	// 2. Restore disk overlay if present in snapshot
	snapOverlay := filepath.Join(targetSnapDir, "overlay.qcow2")
	currOverlay := filepath.Join(dir, "overlay.qcow2")
	if _, err := os.Stat(snapOverlay); err == nil {
		_ = cow.RemoveOverlay(currOverlay)
		_ = os.Remove(currOverlay)
		// Branch from snapOverlay as new active overlay
		if err := cow.CreateOverlay(nil, snapOverlay, currOverlay); err != nil {
			// Fallback: copy file
			if data, rerr := os.ReadFile(snapOverlay); rerr == nil {
				_ = os.WriteFile(currOverlay, data, 0644)
			}
		}
	}

	// 3. Restore state machine
	currentState, _ := state.LoadState(taskID)
	fromStatus := state.StatusRunning
	if currentState != nil {
		fromStatus = currentState.Status
	}

	snapStatePath := filepath.Join(targetSnapDir, "state.json")
	targetState := &state.ContainerState{}
	if stateBytes, err := os.ReadFile(snapStatePath); err == nil {
		_ = json.Unmarshal(stateBytes, targetState)
	} else if currentState != nil {
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
