package snapshot

import (
	"os"
	"testing"
	"time"

	"uml-container/internal/state"
)

func TestEventSnapshot_CreateListGetDelete(t *testing.T) {
	tmpDir := t.TempDir()
	orig := state.RootDir
	state.RootDir = tmpDir
	defer func() { state.RootDir = orig }()

	taskID := "test-event-task"
	cDir, err := state.ContainerDir(taskID)
	if err != nil {
		t.Fatalf("ContainerDir: %v", err)
	}
	if err := os.MkdirAll(cDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	st := &state.ContainerState{
		ID:        taskID,
		Status:    state.StatusRunning,
		StartedAt: time.Now().UTC(),
	}
	if err := state.SaveState(taskID, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	var snap1 *EventSnapshot

	t.Run("CreateSnapshots", func(t *testing.T) {
		meta := map[string]string{"action": "exec_test", "user": "alice"}
		var err error
		snap1, err = CreateEventSnapshot(taskID, "event-001", "hash-abc-123", meta)
		if err != nil {
			t.Fatalf("CreateEventSnapshot: %v", err)
		}
		if snap1.TaskID != taskID {
			t.Errorf("snap1.TaskID = %q, want %q", snap1.TaskID, taskID)
		}
		if snap1.EventID != "event-001" {
			t.Errorf("snap1.EventID = %q, want %q", snap1.EventID, "event-001")
		}
		if snap1.AuditHash != "hash-abc-123" {
			t.Errorf("snap1.AuditHash = %q, want %q", snap1.AuditHash, "hash-abc-123")
		}

		snap2, err := CreateEventSnapshot(taskID, "event-002", "hash-def-456", nil)
		if err != nil || snap2 == nil {
			t.Fatalf("CreateEventSnapshot 2: %v", err)
		}
	})

	t.Run("ListSnapshots", func(t *testing.T) {
		list, err := ListEventSnapshots(taskID)
		if err != nil {
			t.Fatalf("ListEventSnapshots: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("ListEventSnapshots count = %d, want 2", len(list))
		}
	})

	t.Run("GetSnapshot", func(t *testing.T) {
		got, err := GetEventSnapshot(taskID, snap1.ID)
		if err != nil {
			t.Fatalf("GetEventSnapshot: %v", err)
		}
		if got.ID != snap1.ID || got.Metadata["action"] != "exec_test" {
			t.Errorf("GetEventSnapshot mismatch: %+v", got)
		}
	})

	t.Run("DeleteSnapshot", func(t *testing.T) {
		if err := DeleteEventSnapshot(taskID, snap1.ID); err != nil {
			t.Fatalf("DeleteEventSnapshot: %v", err)
		}
		listAfter, err := ListEventSnapshots(taskID)
		if err != nil {
			t.Fatalf("ListEventSnapshots after delete: %v", err)
		}
		if len(listAfter) != 1 {
			t.Fatalf("ListEventSnapshots after delete count = %d, want 1", len(listAfter))
		}
	})

	t.Run("GetNonExistentSnapshot", func(t *testing.T) {
		if _, err := GetEventSnapshot(taskID, "non-existent"); err == nil {
			t.Fatal("expected error getting non-existent snapshot")
		}
	})
}

func TestEventSnapshot_Validation(t *testing.T) {
	tmpDir := t.TempDir()
	orig := state.RootDir
	state.RootDir = tmpDir
	defer func() { state.RootDir = orig }()

	cases := []struct {
		name    string
		taskID  string
		wantErr bool
	}{
		{"SlashInTaskID", "bad/id", true},
		{"TraversalInTaskID", "../../etc", true},
		{"EmptyTaskID", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CreateEventSnapshot(tc.taskID, "event-1", "", nil); (err != nil) != tc.wantErr {
				t.Errorf("CreateEventSnapshot(%q) err = %v, wantErr = %v", tc.taskID, err, tc.wantErr)
			}
			if _, err := ListEventSnapshots(tc.taskID); (err != nil) != tc.wantErr {
				t.Errorf("ListEventSnapshots(%q) err = %v, wantErr = %v", tc.taskID, err, tc.wantErr)
			}
		})
	}
}
