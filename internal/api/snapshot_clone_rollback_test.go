package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"uml-container/internal/snapshot"
	"uml-container/internal/state"

	"github.com/labstack/echo/v4"
)

func setupTestServer(t *testing.T) (*echo.Echo, string) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("PVM_STATE_ROOT", filepath.Join(tmp, "containers"))
	t.Setenv("PVM_AUDIT_ROOT", filepath.Join(tmp, "audit"))
	t.Setenv("PVM_VOLUME_ROOT", filepath.Join(tmp, "volumes"))
	t.Setenv("API_SECRET", "test-secret")

	origStateRoot := state.RootDir
	state.RootDir = filepath.Join(tmp, "containers")
	t.Cleanup(func() {
		state.RootDir = origStateRoot
	})

	e, err := NewE2BServer()
	if err != nil {
		t.Fatalf("NewE2BServer: %v", err)
	}

	return e, tmp
}

func TestAPI_EventSnapshotLifecycle(t *testing.T) {
	e, _ := setupTestServer(t)

	taskID := "task-api-snap"
	cDir, _ := state.ContainerDir(taskID)
	_ = os.MkdirAll(cDir, 0755)
	_ = state.SaveState(taskID, &state.ContainerState{
		ID:        taskID,
		Status:    state.StatusRunning,
		StartedAt: time.Now().UTC(),
	})

	// 1. POST /api/tasks/:id/snapshots
	body := `{"event_id":"step-1","audit_hash":"hash-123","metadata":{"action":"init"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+taskID+"/snapshots", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST snapshot code = %d, body: %s", rec.Code, rec.Body.String())
	}
	var snap snapshot.EventSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if snap.EventID != "step-1" || snap.AuditHash != "hash-123" {
		t.Errorf("unexpected snapshot: %+v", snap)
	}

	// 2. GET /api/tasks/:id/snapshots
	reqList := httptest.NewRequest(http.MethodGet, "/api/tasks/"+taskID+"/snapshots", nil)
	reqList.Header.Set("Authorization", "Bearer test-secret")
	recList := httptest.NewRecorder()
	e.ServeHTTP(recList, reqList)

	if recList.Code != http.StatusOK {
		t.Fatalf("GET snapshots code = %d", recList.Code)
	}
	var list []snapshot.EventSnapshot
	if err := json.Unmarshal(recList.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("unexpected list: %s (err=%v)", recList.Body.String(), err)
	}

	// 3. GET /api/tasks/:id/snapshots/:snapId
	reqGet := httptest.NewRequest(http.MethodGet, "/api/tasks/"+taskID+"/snapshots/"+snap.ID, nil)
	reqGet.Header.Set("Authorization", "Bearer test-secret")
	recGet := httptest.NewRecorder()
	e.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("GET single snapshot code = %d", recGet.Code)
	}

	// 4. POST /api/tasks/:id/clone
	cloneBody := `{"new_id":"task-api-cloned"}`
	reqClone := httptest.NewRequest(http.MethodPost, "/api/tasks/"+taskID+"/clone", bytes.NewBufferString(cloneBody))
	reqClone.Header.Set("Content-Type", "application/json")
	reqClone.Header.Set("Authorization", "Bearer test-secret")
	recClone := httptest.NewRecorder()
	e.ServeHTTP(recClone, reqClone)

	if recClone.Code != http.StatusOK {
		t.Fatalf("POST clone code = %d, body: %s", recClone.Code, recClone.Body.String())
	}

	// 5. POST /api/tasks/:id/rollback
	rbBody := `{"snapshot_id":"` + snap.ID + `"}`
	reqRb := httptest.NewRequest(http.MethodPost, "/api/tasks/"+taskID+"/rollback", bytes.NewBufferString(rbBody))
	reqRb.Header.Set("Content-Type", "application/json")
	reqRb.Header.Set("Authorization", "Bearer test-secret")
	recRb := httptest.NewRecorder()
	e.ServeHTTP(recRb, reqRb)

	if recRb.Code != http.StatusOK {
		t.Fatalf("POST rollback code = %d, body: %s", recRb.Code, recRb.Body.String())
	}
}
