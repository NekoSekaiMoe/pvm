// Kernel-free tests for the E2B SDK compatibility surface (e2b_compat.go):
// auth header variants, list shape, error contract ({message} bodies), and
// the short-ID resolver used by kill/refresh.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"uml-container/internal/state"
)

func newCompatEcho(t *testing.T) *echo.Echo {
	t.Helper()
	t.Setenv("API_SECRET", "secret")
	state.RootDir = t.TempDir()
	e, err := NewE2BServer()
	if err != nil {
		t.Fatalf("NewE2BServer: %v", err)
	}
	return e
}

// doCompat performs a request against the compat surface. key is sent as
// X-API-KEY; bearer alternates to the Authorization header.
func doCompat(t *testing.T, e *echo.Echo, method, path, key, body string, bearer bool) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer {
		req.Header.Set("Authorization", "Bearer "+key)
	} else {
		req.Header.Set("X-API-KEY", key)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestE2BCompatAuth(t *testing.T) {
	e := newCompatEcho(t)

	rec := doCompat(t, e, http.MethodGet, "/sandboxes", "", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["message"] == "" {
		t.Fatalf("no key: error body must carry {\"message\"}: %s", rec.Body.String())
	}

	rec = doCompat(t, e, http.MethodGet, "/sandboxes", "wrong", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: expected 401, got %d", rec.Code)
	}

	rec = doCompat(t, e, http.MethodGet, "/sandboxes", "secret", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("Bearer key: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestE2BCompatListShape(t *testing.T) {
	e := newCompatEcho(t)

	rec := doCompat(t, e, http.MethodGet, "/sandboxes", "secret", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &arr); err != nil {
		t.Fatalf("empty list must be a JSON array: %s", rec.Body.String())
	}
	if len(arr) != 0 {
		t.Fatalf("empty state must list zero sandboxes, got %s", rec.Body.String())
	}

	// Fabricate a task and verify the SDK-facing field names.
	started := time.Now().UTC().Add(-time.Minute)
	if err := state.SaveState("sbxunit1", &state.ContainerState{
		ID:        "sbxunit1",
		Name:      "sbxunit1",
		Status:    state.StatusReady,
		StartedAt: started,
	}); err != nil {
		t.Fatal(err)
	}

	rec = doCompat(t, e, http.MethodGet, "/sandboxes", "secret", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("list after save: expected 200, got %d", rec.Code)
	}
	var views []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 view, got %d: %s", len(views), rec.Body.String())
	}
	v := views[0]
	for _, field := range []string{"sandboxID", "clientID", "templateID", "cpuCount", "memoryMB", "startedAt"} {
		if _, ok := v[field]; !ok {
			t.Fatalf("SDK field %q missing from view: %v", field, v)
		}
	}
	if v["sandboxID"] != "sbxunit1" {
		t.Fatalf("sandboxID = %v", v["sandboxID"])
	}
}

func TestE2BCompatErrorContract(t *testing.T) {
	e := newCompatEcho(t)

	// create without templateID -> 400 {"message"} (SDK "bad request" path)
	rec := doCompat(t, e, http.MethodPost, "/sandboxes", "secret", `{}`, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create empty: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["message"] == "" {
		t.Fatalf("create empty: must carry {\"message\"}: %s", rec.Body.String())
	}

	// kill unknown -> 404 {"message"}
	rec = doCompat(t, e, http.MethodDelete, "/sandboxes/ghost", "secret", "", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("kill ghost: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	body = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body == nil || body["message"] == "" {
		t.Fatalf("kill ghost: must carry {\"message\"}: %s", rec.Body.String())
	}

	// refresh unknown -> 404 {"message"}
	rec = doCompat(t, e, http.MethodPost, "/sandboxes/ghost/refreshes", "secret", `{"duration":60}`, false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("refresh ghost: expected 404, got %d", rec.Code)
	}

	// refresh out-of-range duration -> 400
	if err := state.SaveState("sbxunit2", &state.ContainerState{ID: "sbxunit2", Name: "sbxunit2", Status: state.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	rec = doCompat(t, e, http.MethodPost, "/sandboxes/sbxunit2/refreshes", "secret", `{"duration":9999}`, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("refresh out of range: expected 400, got %d", rec.Code)
	}
}

func TestE2BCompatRefreshAndKill(t *testing.T) {
	e := newCompatEcho(t)

	if err := state.SaveState("sbxkill1", &state.ContainerState{
		ID:     "sbxkill1",
		Name:   "sbxkill1",
		Status: state.StatusRunning,
	}); err != nil {
		t.Fatal(err)
	}

	// refresh pushes Deadline into the future.
	before := time.Now().UTC()
	rec := doCompat(t, e, http.MethodPost, "/sandboxes/sbxkill1/refreshes", "secret", `{"duration":120}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	st, err := state.LoadState("sbxkill1")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Deadline.After(before) {
		t.Fatalf("refresh did not extend deadline: %v", st.Deadline)
	}

	// kill removes the task (directory + list).
	rec = doCompat(t, e, http.MethodDelete, "/sandboxes/sbxkill1", "secret", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("kill: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	all, err := state.ListAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range all {
		if st.ID == "sbxkill1" {
			t.Fatal("kill left the task in state")
		}
	}

	// The short-ID resolver must not treat distinct dash-free IDs as prefixes
	// of each other after the kill.
	rec = doCompat(t, e, http.MethodDelete, "/sandboxes/sbxkill1", "secret", "", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("re-kill: expected 404, got %d", rec.Code)
	}
}

func TestE2BCompatMetadataRoundTrip(t *testing.T) {
	e := newCompatEcho(t)

	// The create handler itself needs a UML kernel (unavailable in CI), so
	// persistence is exercised at the state layer: metadata written at
	// create time must survive Save/Load and surface in the list view.
	meta := map[string]string{"env": "prod", "team": "agent"}
	if err := state.SaveState("sbxmeta1", &state.ContainerState{
		ID:        "sbxmeta1",
		Name:      "sbxmeta1",
		Status:    state.StatusReady,
		StartedAt: time.Now().UTC(),
		Metadata:  meta,
	}); err != nil {
		t.Fatal(err)
	}
	st, err := state.LoadState("sbxmeta1")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Metadata) != len(meta) || st.Metadata["env"] != "prod" || st.Metadata["team"] != "agent" {
		t.Fatalf("metadata not persisted: %v", st.Metadata)
	}

	rec := doCompat(t, e, http.MethodGet, "/sandboxes", "secret", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var views []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 view, got %d: %s", len(views), rec.Body.String())
	}
	got, ok := views[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata missing from view: %v", views[0])
	}
	if got["env"] != "prod" || got["team"] != "agent" {
		t.Fatalf("metadata mismatch in view: %v", got)
	}

	// A sandbox without metadata must omit the field (omitempty contract).
	if err := state.SaveState("sbxmeta2", &state.ContainerState{ID: "sbxmeta2", Name: "sbxmeta2", Status: state.StatusReady}); err != nil {
		t.Fatal(err)
	}
	rec = doCompat(t, e, http.MethodGet, "/sandboxes", "secret", "", false)
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatalf("list body: %v", err)
	}
	for _, v := range views {
		if v["sandboxID"] == "sbxmeta2" {
			if _, present := v["metadata"]; present {
				t.Fatalf("metadata must be omitted when empty: %v", v)
			}
		}
	}
}

func TestE2BCompatAmbiguousPrefix(t *testing.T) {
	e := newCompatEcho(t)

	for _, id := range []string{"projA1", "projA2"} {
		if err := state.SaveState(id, &state.ContainerState{ID: id, Name: id, Status: state.StatusReady}); err != nil {
			t.Fatal(err)
		}
	}
	// "projA" is a prefix of both -> ambiguous -> 409.
	rec := doCompat(t, e, http.MethodDelete, "/sandboxes/projA", "secret", "", false)
	if rec.Code != http.StatusConflict {
		t.Fatalf("ambiguous prefix: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	// exact match still resolves.
	rec = doCompat(t, e, http.MethodDelete, "/sandboxes/projA1", "secret", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("exact kill: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
