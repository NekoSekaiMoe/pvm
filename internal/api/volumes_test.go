package api

// Volume REST lifecycle tests: builtin volumes are provisioned as real cow
// block images at create time, snapshots have REST endpoints, rollback/clone
// respect the engine's reference guards, and DELETE cleans both the block
// image and the metadata record. Non-builtin drivers stay metadata-only.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAPI_VolumeLifecycle(t *testing.T) {
	e, _ := setupTestServer(t)
	volRoot := os.Getenv("PVM_VOLUME_ROOT")

	do := func(t *testing.T, method, path, body string) (*httptest.ResponseRecorder, map[string]interface{}) {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-secret")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		var resp map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec, resp
	}
	qcow2Magic := func(t *testing.T, path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if len(data) < 4 || string(data[:3]) != "QFI" {
			t.Fatalf("%s is not a qcow2 image", path)
		}
	}

	t.Run("CreateBuiltinProvisionsBlock", func(t *testing.T) {
		rec, resp := do(t, http.MethodPost, "/api/volumes", `{"name":"v-life","driver":"builtin","size":1048576}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create code = %d, body: %s", rec.Code, rec.Body.String())
		}
		if resp["volume_id"] != "v-life" {
			t.Fatalf("volume_id = %v", resp["volume_id"])
		}
		qcow2Magic(t, filepath.Join(volRoot, "v-life.qcow2"))
	})

	t.Run("DuplicateCreateReturns409", func(t *testing.T) {
		if rec, _ := do(t, http.MethodPost, "/api/volumes", `{"name":"v-life","driver":"builtin"}`); rec.Code != http.StatusConflict {
			t.Errorf("duplicate create code = %d, want 409", rec.Code)
		}
	})

	t.Run("ReservedSnapshotPrefixRejected", func(t *testing.T) {
		if rec, _ := do(t, http.MethodPost, "/api/volumes", `{"name":"snap-evil","driver":"builtin"}`); rec.Code != http.StatusBadRequest {
			t.Errorf("snap- prefix create code = %d, want 400", rec.Code)
		}
	})

	t.Run("EmptySnapshotList", func(t *testing.T) {
		rec, _ := do(t, http.MethodGet, "/api/volumes/v-life/snapshots", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list snapshots code = %d", rec.Code)
		}
		var list []interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("snapshot list must be a JSON array, got: %s (err=%v)", rec.Body.String(), err)
		}
		if len(list) != 0 {
			t.Fatalf("expected empty snapshot list, got: %s", rec.Body.String())
		}
	})

	t.Run("CreateSnapshot", func(t *testing.T) {
		rec, resp := do(t, http.MethodPost, "/api/volumes/v-life/snapshots", `{"snapshot":"s1"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create snapshot code = %d, body: %s", rec.Code, rec.Body.String())
		}
		if resp["snapshot"] != "s1" {
			t.Fatalf("snapshot = %v", resp["snapshot"])
		}
		qcow2Magic(t, filepath.Join(volRoot, "snap-s1.qcow2"))
	})

	t.Run("DuplicateSnapshotReturns409", func(t *testing.T) {
		if rec, _ := do(t, http.MethodPost, "/api/volumes/v-life/snapshots", `{"snapshot":"s1"}`); rec.Code != http.StatusConflict {
			t.Errorf("duplicate snapshot code = %d, want 409", rec.Code)
		}
	})

	t.Run("SnapshotUnknownVolumeReturns404", func(t *testing.T) {
		if rec, _ := do(t, http.MethodPost, "/api/volumes/no-such-vol/snapshots", `{"snapshot":"sx"}`); rec.Code != http.StatusNotFound {
			t.Errorf("unknown volume snapshot code = %d, want 404", rec.Code)
		}
	})

	t.Run("SnapshotListContainsOrigin", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/volumes/v-life/snapshots", nil)
		req.Header.Set("Authorization", "Bearer test-secret")
		e.ServeHTTP(rec, req)
		var snaps []struct {
			Name         string `json:"name"`
			OriginVolume string `json:"origin_volume"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &snaps); err != nil || len(snaps) != 1 {
			t.Fatalf("unexpected snapshot list: %s (err=%v)", rec.Body.String(), err)
		}
		if snaps[0].Name != "s1" || snaps[0].OriginVolume != "v-life" {
			t.Fatalf("snapshot = %+v, want name=s1 origin=v-life", snaps[0])
		}
	})

	t.Run("CloneVolume", func(t *testing.T) {
		rec, resp := do(t, http.MethodPost, "/api/volumes/v-life/clone", `{"new_id":"v-clone-a"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("clone code = %d, body: %s", rec.Code, rec.Body.String())
		}
		if resp["status"] != "cloned" {
			t.Fatalf("status = %v", resp["status"])
		}
		qcow2Magic(t, filepath.Join(volRoot, "v-clone-a.qcow2"))
	})

	t.Run("RollbackWithDependentReturns409", func(t *testing.T) {
		if rec, _ := do(t, http.MethodPost, "/api/volumes/v-life/rollback", `{"snapshot":"s1"}`); rec.Code != http.StatusConflict {
			t.Errorf("rollback with dependent code = %d, want 409", rec.Code)
		}
	})

	t.Run("DeleteReferencedVolumeReturns409", func(t *testing.T) {
		if rec, _ := do(t, http.MethodDelete, "/api/volumes/v-life", ""); rec.Code != http.StatusConflict {
			t.Errorf("delete referenced volume code = %d, want 409", rec.Code)
		}
	})

	t.Run("DeleteCloneCleansBlock", func(t *testing.T) {
		if rec, _ := do(t, http.MethodDelete, "/api/volumes/v-clone-a", ""); rec.Code != http.StatusNoContent {
			t.Fatalf("delete clone code = %d, want 204", rec.Code)
		}
		if _, err := os.Stat(filepath.Join(volRoot, "v-clone-a.qcow2")); !os.IsNotExist(err) {
			t.Fatalf("cloned block file must be removed, stat err = %v", err)
		}
	})

	t.Run("RollbackSucceedsWithTargetSnapshotExcluded", func(t *testing.T) {
		rec, resp := do(t, http.MethodPost, "/api/volumes/v-life/rollback", `{"snapshot":"s1"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("rollback code = %d, body: %s", rec.Code, rec.Body.String())
		}
		if resp["status"] != "rolled_back" {
			t.Fatalf("status = %v", resp["status"])
		}
		// The restored volume is a standalone qcow2 (convert, not overlay).
		qcow2Magic(t, filepath.Join(volRoot, "v-life.qcow2"))
	})

	t.Run("DeleteSnapshotAndVolume", func(t *testing.T) {
		if rec, _ := do(t, http.MethodDelete, "/api/volumes/v-life/snapshots/s1", ""); rec.Code != http.StatusNoContent {
			t.Fatalf("delete snapshot code = %d, want 204", rec.Code)
		}
		if _, err := os.Stat(filepath.Join(volRoot, "snap-s1.qcow2")); !os.IsNotExist(err) {
			t.Fatalf("snapshot file must be removed, stat err = %v", err)
		}
		if rec, _ := do(t, http.MethodDelete, "/api/volumes/v-life", ""); rec.Code != http.StatusNoContent {
			t.Fatalf("delete volume code = %d, want 204", rec.Code)
		}
		if _, err := os.Stat(filepath.Join(volRoot, "v-life.qcow2")); !os.IsNotExist(err) {
			t.Fatalf("volume block must be removed, stat err = %v", err)
		}
		if rec, _ := do(t, http.MethodGet, "/api/volumes/v-life", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("volume record must be gone, code = %d", rec.Code)
		}
	})

	t.Run("NonBuiltinDriverStaysMetadataOnly", func(t *testing.T) {
		if rec, _ := do(t, http.MethodPost, "/api/volumes", `{"name":"v-nfs","driver":"nfs"}`); rec.Code != http.StatusCreated {
			t.Fatalf("nfs create code = %d", rec.Code)
		}
		if _, err := os.Stat(filepath.Join(volRoot, "v-nfs.qcow2")); !os.IsNotExist(err) {
			t.Fatalf("non-builtin volume must not get a block image, stat err = %v", err)
		}
		if rec, _ := do(t, http.MethodPost, "/api/volumes/v-nfs/clone", `{"new_id":"v-nfs-clone"}`); rec.Code != http.StatusNotFound {
			t.Errorf("clone of metadata-only volume code = %d, want 404", rec.Code)
		}
		if rec, _ := do(t, http.MethodDelete, "/api/volumes/v-nfs", ""); rec.Code != http.StatusNoContent {
			t.Errorf("nfs delete code = %d, want 204", rec.Code)
		}
	})
}
