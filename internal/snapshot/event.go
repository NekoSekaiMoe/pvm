package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"uml-container/internal/cow"
	"uml-container/internal/state"
)

// EventSnapshot represents a point-in-time snapshot linked to a specific event
// and its cryptographic audit hash chain entry.
type EventSnapshot struct {
	ID          string            `json:"id"`
	TaskID      string            `json:"task_id"`
	EventID     string            `json:"event_id"`
	AuditHash   string            `json:"audit_hash,omitempty"`
	StateStatus string            `json:"state_status,omitempty"`
	DiskOverlay string            `json:"disk_overlay,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

var eventSnapshotMu sync.Mutex

// pidMatchesStart reports whether pid still names the process started at
// (approximately) want. It compares /proc/<pid>/stat's starttime against the
// recorded StartedAt: a reused PID belongs to a process born AFTER the task
// started, so a mismatch means the memory dump would capture a stranger.
func pidMatchesStart(pid int, want time.Time) bool {
	if want.IsZero() {
		return true // no recorded start time: cannot verify, keep legacy behavior
	}
	started := procStartTime(pid)
	if started.IsZero() {
		// /proc unreadable (non-Linux, already-dead pid): a dead pid cannot
		// be dumped anyway — let CRIU surface the real error.
		return true
	}
	// Clock skew between procfs starttime and our wall-clock StartedAt can
	// be a second or two; a reused PID is typically off by minutes/hours.
	return !started.After(want.Add(5 * time.Second))
}

// procStartTime returns the wall-clock start time of pid from /proc, or the
// zero time when it cannot be determined.
func procStartTime(pid int) time.Time {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return time.Time{}
	}
	// comm (field 2) may contain spaces inside parens; everything after the
	// LAST ')' is field 3 onward, and starttime is field 22 → index 19.
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 || i+2 >= len(raw) {
		return time.Time{}
	}
	fields := strings.Fields(string(raw[i+2:]))
	if len(fields) < 20 {
		return time.Time{}
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}
	}
	boot := procBootTime()
	if boot.IsZero() {
		return time.Time{}
	}
	return boot.Add(time.Duration(ticks) * (time.Second / 100))
}

// procBootTime returns the system boot time from /proc/stat's btime line.
func procBootTime() time.Time {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		sec, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime")), 10, 64)
		if err != nil {
			return time.Time{}
		}
		return time.Unix(sec, 0)
	}
	return time.Time{}
}

func snapshotsDir(containerID string) (string, error) {
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "snapshots"), nil
}

// CreateEventSnapshot creates an event-level snapshot for a task/container.
// It snapshots the container state and disk overlay/files into a designated
// snapshot directory and links it with the audit trail hash.
func CreateEventSnapshot(taskID, eventID, auditHash string, metadata map[string]string) (*EventSnapshot, error) {
	if !validContainerID.MatchString(taskID) {
		return nil, fmt.Errorf("snapshot: invalid task id %q", taskID)
	}
	if eventID == "" {
		eventID = "manual"
	}

	eventSnapshotMu.Lock()
	defer eventSnapshotMu.Unlock()

	dir, err := state.ContainerDir(taskID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("snapshot: container dir not found for %s: %w", taskID, err)
	}

	st, err := state.LoadState(taskID)
	if err != nil {
		return nil, fmt.Errorf("snapshot: load state for %s: %w", taskID, err)
	}

	snapDir, err := snapshotsDir(taskID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(snapDir, 0755); err != nil {
		return nil, fmt.Errorf("snapshot: create snapshot dir: %w", err)
	}

	now := time.Now().UTC()
	snapID := fmt.Sprintf("snap-%s-%d", taskID, now.UnixNano())
	targetDir := filepath.Join(snapDir, snapID)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("snapshot: create target snap dir: %w", err)
	}

	// 0. Memory state (CRIU): a Running guest with a live pid gets a
	// checkpoint-and-continue dump; without criu the snapshot proceeds with
	// memory_state=degraded — disk + FSM only, restore boots fresh.
	if metadata == nil {
		metadata = map[string]string{}
	} else {
		metadata = copyMeta(metadata)
	}
	dumpMemory := st.PID > 0 && st.Status == state.StatusRunning
	if dumpMemory && !pidMatchesStart(st.PID, st.StartedAt) {
		// The recorded PID now names a DIFFERENT process (PID reuse after a
		// crash): dumping it would write a stranger's memory into this task's
		// snapshot. Skip memory instead of capturing the wrong process.
		dumpMemory = false
		metadata["memory_state"] = string(MemoryNotAttempt)
		metadata["memory_error"] = fmt.Sprintf("pid %d does not match recorded start time (possible PID reuse)", st.PID)
	}
	// Consistency barrier: freeze the guest for BOTH captures so the CRIU
	// memory image and the disk overlay describe the same instant. Without
	// this the guest keeps running between the two steps and a MemoryFull
	// restore would combine an old memory image with newer disk writes.
	frozen := false
	if dumpMemory {
		if kerr := syscall.Kill(st.PID, syscall.SIGSTOP); kerr == nil {
			frozen = true
		}
	}
	// Safety net for every early return below; normally cleared explicitly
	// once the overlay capture finishes.
	defer func() {
		if frozen {
			syscall.Kill(st.PID, syscall.SIGCONT)
		}
	}()
	if dumpMemory {
		if err := DumpMemory(st.PID, MemoryImagesDir(targetDir), true); err == nil {
			metadata["memory_state"] = string(MemoryFull)
		} else {
			metadata["memory_state"] = string(MemoryDegraded)
			metadata["memory_error"] = err.Error()
		}
	} else if _, attempted := metadata["memory_state"]; !attempted {
		metadata["memory_state"] = string(MemoryNotAttempt)
	}

	// 1. Snapshot state.json
	stateSrc := filepath.Join(dir, "state.json")
	if data, err := os.ReadFile(stateSrc); err == nil {
		if err := os.WriteFile(filepath.Join(targetDir, "state.json"), data, 0644); err != nil {
			os.RemoveAll(targetDir)
			return nil, fmt.Errorf("snapshot: save state copy: %w", err)
		}
	}

	// 2. Snapshot disk overlay (if qcow2 overlay exists)
	overlaySrc := filepath.Join(dir, "overlay.qcow2")
	overlayDst := ""
	if _, err := os.Stat(overlaySrc); err == nil {
		overlayDst = filepath.Join(targetDir, "overlay.qcow2")
		// Create a new overlay branching from the current overlay (instant copy)
		if err := cow.CreateOverlay(context.Background(), overlaySrc, overlayDst); err != nil {
			// Fallback: stream-copy the file — a disk overlay can be far
			// larger than memory, so never buffer it whole via ReadFile. When
			// the fallback ALSO fails, abort the snapshot: recording a
			// DiskOverlay that was never written and reporting success would
			// corrupt later rollbacks that branch from this snapshot.
			if cerr := copyFile(overlaySrc, overlayDst); cerr != nil {
				os.RemoveAll(targetDir)
				return nil, fmt.Errorf("snapshot: capture overlay: overlay branch: %v; fallback copy: %w", err, cerr)
			}
		}
	}
	// Both captures (memory + overlay) are complete: thaw the guest.
	if frozen {
		frozen = false
		syscall.Kill(st.PID, syscall.SIGCONT)
	}

	if metadata == nil {
		metadata = make(map[string]string)
	}

	snap := &EventSnapshot{
		ID:          snapID,
		TaskID:      taskID,
		EventID:     eventID,
		AuditHash:   auditHash,
		StateStatus: string(st.Status),
		DiskOverlay: overlayDst,
		CreatedAt:   now,
		Metadata:    metadata,
	}

	metaBytes, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		os.RemoveAll(targetDir)
		return nil, fmt.Errorf("snapshot: marshal metadata: %w", err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "snapshot.json"), metaBytes, 0644); err != nil {
		os.RemoveAll(targetDir)
		return nil, fmt.Errorf("snapshot: write metadata: %w", err)
	}

	return snap, nil
}

// ListEventSnapshots lists all event snapshots recorded for a task.
func ListEventSnapshots(taskID string) ([]EventSnapshot, error) {
	if !validContainerID.MatchString(taskID) {
		return nil, fmt.Errorf("snapshot: invalid task id %q", taskID)
	}

	eventSnapshotMu.Lock()
	defer eventSnapshotMu.Unlock()

	snapDir, err := snapshotsDir(taskID)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(snapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []EventSnapshot{}, nil
		}
		return nil, fmt.Errorf("snapshot: read snap dir: %w", err)
	}

	var snapshots []EventSnapshot
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		metaPath := filepath.Join(snapDir, ent.Name(), "snapshot.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var s EventSnapshot
		if err := json.Unmarshal(data, &s); err == nil {
			snapshots = append(snapshots, s)
		}
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].CreatedAt.Before(snapshots[j].CreatedAt)
	})
	if snapshots == nil {
		snapshots = []EventSnapshot{}
	}
	return snapshots, nil
}

// GetEventSnapshot retrieves a specific event snapshot for a task.
func GetEventSnapshot(taskID, snapshotID string) (*EventSnapshot, error) {
	if !validContainerID.MatchString(taskID) {
		return nil, fmt.Errorf("snapshot: invalid task id %q", taskID)
	}
	if !validContainerID.MatchString(snapshotID) {
		return nil, fmt.Errorf("snapshot: invalid snapshot id %q", snapshotID)
	}

	eventSnapshotMu.Lock()
	defer eventSnapshotMu.Unlock()

	snapDir, err := snapshotsDir(taskID)
	if err != nil {
		return nil, err
	}
	metaPath := filepath.Join(snapDir, snapshotID, "snapshot.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("snapshot %q not found for task %q", snapshotID, taskID)
		}
		return nil, fmt.Errorf("snapshot: read meta: %w", err)
	}
	var s EventSnapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("snapshot: parse meta: %w", err)
	}
	return &s, nil
}

// DeleteEventSnapshot removes a specific event snapshot.
func DeleteEventSnapshot(taskID, snapshotID string) error {
	if !validContainerID.MatchString(taskID) {
		return fmt.Errorf("snapshot: invalid task id %q", taskID)
	}
	if !validContainerID.MatchString(snapshotID) {
		return fmt.Errorf("snapshot: invalid snapshot id %q", snapshotID)
	}

	eventSnapshotMu.Lock()
	defer eventSnapshotMu.Unlock()

	snapDir, err := snapshotsDir(taskID)
	if err != nil {
		return err
	}
	targetDir := filepath.Join(snapDir, snapshotID)
	if _, err := os.Stat(targetDir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("snapshot %q not found", snapshotID)
		}
		return err
	}
	// Refuse while a live backing chain (this container's active overlay,
	// a clone's, or a sibling snapshot's) still reaches this snapshot's
	// overlay — deleting it would corrupt the chain at the next read.
	if err := PrepareDeleteEventSnapshot(taskID, snapshotID); err != nil {
		return err
	}
	return os.RemoveAll(targetDir)
}
