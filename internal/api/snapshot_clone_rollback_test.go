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
	os.Setenv("PVM_STATE_ROOT", filepath.Join(tmp, "containers"))
	os.Setenv("PVM_AUDIT_ROOT", filepath.Join(tmp, "audit"))
	os.Setenv("PVM_VOLUME_ROOT", filepath.Join(tmp, "volumes"))
	os.Setenv("API_SECRET", "test-secret")

	e := echo.New()
	api := e.Group("/api")

	// 1. Task snapshots
	api.POST("/tasks/:id/snapshots", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		var req struct {
			EventID   string            `json:"event_id"`
			AuditHash string            `json:"audit_hash"`
			Metadata  map[string]string `json:"metadata"`
		}
		_ = c.Bind(&req)
		snap, err := snapshot.CreateEventSnapshot(id, req.EventID, req.AuditHash, req.Metadata)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, snap)
	})

	api.GET("/tasks/:id/snapshots", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		list, err := snapshot.ListEventSnapshots(id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, list)
	})

	api.GET("/tasks/:id/snapshots/:snapId", func(c echo.Context) error {
		id := c.Param("id")
		snapId := c.Param("snapId")
		if !idRegex.MatchString(id) || !idRegex.MatchString(snapId) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id format"})
		}
		snap, err := snapshot.GetEventSnapshot(id, snapId)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, snap)
	})

	// 2. Clone
	api.POST("/tasks/:id/clone", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid source task id"})
		}
		var req struct {
			NewID string `json:"new_id"`
		}
		if err := c.Bind(&req); err != nil || req.NewID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "new_id is required"})
		}
		if !idRegex.MatchString(req.NewID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid new_id format"})
		}
		if err := snapshot.Clone(id, req.NewID); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "cloned", "id": req.NewID, "source_id": id})
	})

	// 3. Rollback
	api.POST("/tasks/:id/rollback", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		var req struct {
			SnapshotID string `json:"snapshot_id"`
		}
		if err := c.Bind(&req); err != nil || req.SnapshotID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "snapshot_id is required"})
		}
		if !idRegex.MatchString(req.SnapshotID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid snapshot_id format"})
		}
		if err := snapshot.Rollback(id, req.SnapshotID); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "rolled_back", "id": id, "snapshot_id": req.SnapshotID})
	})

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
	recGet := httptest.NewRecorder()
	e.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("GET single snapshot code = %d", recGet.Code)
	}

	// 4. POST /api/tasks/:id/clone
	cloneBody := `{"new_id":"task-api-cloned"}`
	reqClone := httptest.NewRequest(http.MethodPost, "/api/tasks/"+taskID+"/clone", bytes.NewBufferString(cloneBody))
	reqClone.Header.Set("Content-Type", "application/json")
	recClone := httptest.NewRecorder()
	e.ServeHTTP(recClone, reqClone)

	if recClone.Code != http.StatusOK {
		t.Fatalf("POST clone code = %d, body: %s", recClone.Code, recClone.Body.String())
	}

	// 5. POST /api/tasks/:id/rollback
	rbBody := `{"snapshot_id":"` + snap.ID + `"}`
	reqRb := httptest.NewRequest(http.MethodPost, "/api/tasks/"+taskID+"/rollback", bytes.NewBufferString(rbBody))
	reqRb.Header.Set("Content-Type", "application/json")
	recRb := httptest.NewRecorder()
	e.ServeHTTP(recRb, reqRb)

	if recRb.Code != http.StatusOK {
		t.Fatalf("POST rollback code = %d, body: %s", recRb.Code, recRb.Body.String())
	}
}
