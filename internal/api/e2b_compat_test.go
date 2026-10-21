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
	state.SetRoot(t.TempDir())
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

func TestParseSandboxTimeout(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantDur   time.Duration
		wantNever bool
		wantErr   bool
	}{
		{"omitted uses default", "", defaultSandboxTimeout, false, false},
		{"zero uses default", "0", defaultSandboxTimeout, false, false},
		{"never sentinel", "-1", 0, true, false},
		{"positive seconds", "300", 300 * time.Second, false, false},
		{"below sentinel rejected", "-2", 0, false, true},
		{"non-integer rejected", "soon", 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, never, err := parseSandboxTimeout(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSandboxTimeout(%q) expected error", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSandboxTimeout(%q): %v", tt.raw, err)
			}
			if d != tt.wantDur || never != tt.wantNever {
				t.Fatalf("parseSandboxTimeout(%q) = (%v, %v), want (%v, %v)",
					tt.raw, d, never, tt.wantDur, tt.wantNever)
			}
		})
	}
}

func TestE2BCompatCreateRejectsBadTimeout(t *testing.T) {
	e := newCompatEcho(t)
	rec := doCompat(t, e, http.MethodPost, "/sandboxes?timeout=-5", "secret", `{"templateID":"x"}`, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad timeout: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["message"] == "" {
		t.Fatalf("bad timeout: must carry {\"message\"}: %s", rec.Body.String())
	}
}

func TestNormalizeMCPConfig(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"absent", "", "", false},
		{"null", "null", "", false},
		{"object", `{"github":{"command":"npx","args":["-y","server"]}}`, `{"github":{"command":"npx","args":["-y","server"]}}`, false},
		{"array rejected", `[1,2]`, "", true},
		{"string rejected", `"nope"`, "", true},
		{"number rejected", `42`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeMCPConfig(json.RawMessage(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("normalizeMCPConfig(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestE2BCompatSandboxInfoRetainsPauseMetadata(t *testing.T) {
	e := newCompatEcho(t)

	deadline := time.Now().UTC().Add(10 * time.Minute)
	if err := state.SaveState("sbxinfo1", &state.ContainerState{
		ID:         "sbxinfo1",
		Name:       "tpl-base",
		Status:     state.StatusSuspended,
		Metadata:   map[string]string{"env": "prod"},
		StartedAt:  time.Now().UTC(),
		Deadline:   deadline,
		AutoResume: true,
	}); err != nil {
		t.Fatal(err)
	}

	rec := doCompat(t, e, http.MethodGet, "/sandboxes/sbxinfo1", "secret", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("info: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["state"] != "paused" {
		t.Fatalf("suspended sandbox must report state=paused: %v", body["state"])
	}
	if body["templateID"] != "tpl-base" {
		t.Fatalf("template lost on pause: %v", body["templateID"])
	}
	if md, _ := body["metadata"].(map[string]any); md["env"] != "prod" {
		t.Fatalf("metadata lost on pause: %v", body["metadata"])
	}
	lc, _ := body["lifecycle"].(map[string]any)
	if lc == nil || lc["onTimeout"] != "pause" || lc["autoResume"] != true {
		t.Fatalf("lifecycle not surfaced: %v", body["lifecycle"])
	}

	// Unknown sandbox -> 404 with a {message} body.
	rec = doCompat(t, e, http.MethodGet, "/sandboxes/nope1", "secret", "", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown info: expected 404, got %d", rec.Code)
	}
}

func TestE2BCompatSandboxInfoNoneDeadline(t *testing.T) {
	e := newCompatEcho(t)
	if err := state.SaveState("sbxnever", &state.ContainerState{
		ID: "sbxnever", Name: "t", Status: state.StatusRunning,
	}); err != nil {
		t.Fatal(err)
	}
	rec := doCompat(t, e, http.MethodGet, "/sandboxes/sbxnever", "secret", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("info: %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["state"] != "running" {
		t.Fatalf("running sandbox must report state=running: %v", body["state"])
	}
	if body["endAt"] == "" || body["endAt"] == nil {
		t.Fatalf("endAt must always be present: %v", body)
	}
	lc, _ := body["lifecycle"].(map[string]any)
	if lc == nil || lc["onTimeout"] != "kill" {
		t.Fatalf("default lifecycle must be kill: %v", body["lifecycle"])
	}
}

func TestE2BCompatCreateRejectsBadMCP(t *testing.T) {
	e := newCompatEcho(t)
	rec := doCompat(t, e, http.MethodPost, "/sandboxes", "secret", `{"templateID":"x","mcp":[1,2]}`, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("array mcp: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["message"] == "" {
		t.Fatalf("bad mcp: must carry {\"message\"}: %s", rec.Body.String())
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
	// The create handler itself needs a UML kernel (unavailable in CI), so
	// persistence is exercised at the state layer: metadata written at
	// create time must survive Save/Load and surface in the list view.
	cases := []struct {
		name     string
		id       string
		metadata map[string]string // nil = sandbox without metadata
	}{
		{name: "with metadata", id: "sbxmeta1", metadata: map[string]string{"env": "prod", "team": "agent"}},
		{name: "without metadata omits field", id: "sbxmeta2", metadata: nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Isolated setup per subtest: fresh echo + fresh state root.
			e := newCompatEcho(t)
			if err := state.SaveState(tc.id, &state.ContainerState{
				ID:        tc.id,
				Name:      tc.id,
				Status:    state.StatusReady,
				StartedAt: time.Now().UTC(),
				Metadata:  tc.metadata,
			}); err != nil {
				t.Fatal(err)
			}

			// Save/Load round-trip at the state layer.
			st, err := state.LoadState(tc.id)
			if err != nil {
				t.Fatal(err)
			}
			if tc.metadata == nil {
				if len(st.Metadata) != 0 {
					t.Fatalf("expected no metadata, got %v", st.Metadata)
				}
			} else {
				if len(st.Metadata) != len(tc.metadata) {
					t.Fatalf("metadata not persisted: %v", st.Metadata)
				}
				for k, v := range tc.metadata {
					if st.Metadata[k] != v {
						t.Fatalf("metadata[%q] = %q, want %q (all: %v)", k, st.Metadata[k], v, st.Metadata)
					}
				}
			}

			// List-response contract: present with values, or omitted entirely.
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
			if views[0]["sandboxID"] != tc.id {
				t.Fatalf("sandboxID = %v, want %s", views[0]["sandboxID"], tc.id)
			}
			got, present := views[0]["metadata"]
			if tc.metadata == nil {
				if present {
					t.Fatalf("metadata must be omitted when empty: %v", views[0])
				}
				return
			}
			if !present {
				t.Fatalf("metadata missing from view: %v", views[0])
			}
			gotMap, ok := got.(map[string]any)
			if !ok {
				t.Fatalf("metadata has unexpected shape: %v", got)
			}
			for k, v := range tc.metadata {
				if gotMap[k] != v {
					t.Fatalf("metadata mismatch in view: %v", gotMap)
				}
			}
		})
	}
}

func TestE2BCompatExactMatchBeatsPrefix(t *testing.T) {
	e := newCompatEcho(t)

	for _, id := range []string{"web", "web-container"} {
		if err := state.SaveState(id, &state.ContainerState{ID: id, Name: id, Status: state.StatusReady}); err != nil {
			t.Fatal(err)
		}
	}
	// "web" is an exact ID AND a prefix of "web-container": the exact match
	// must win (200), not collapse into an ambiguous-prefix 409.
	rec := doCompat(t, e, http.MethodDelete, "/sandboxes/web", "secret", "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("exact kill with longer sibling: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// The longer sibling must be untouched.
	if _, err := state.LoadState("web-container"); err != nil {
		t.Fatalf("web-container must survive the exact kill of web: %v", err)
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

// TestE2BCompatConnect covers Sandbox.connect(): a bare connect returns the
// info view and leaves the deadline alone, a connect with `timeout` applies
// the three-value contract, and a missing sandbox is 404.
func TestE2BCompatConnect(t *testing.T) {
	e := newCompatEcho(t)
	deadline := time.Now().UTC().Add(30 * time.Minute)
	if err := state.SaveState("sbxconn1", &state.ContainerState{
		ID:        "sbxconn1",
		Name:      "sbxconn1",
		Status:    state.StatusRunning,
		Deadline:  deadline,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// Bare connect: 200 with the info shape, deadline untouched.
	rec := doCompat(t, e, http.MethodPost, "/sandboxes/sbxconn1/connect", "secret", `{}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var info map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("connect body: %v", err)
	}
	if info["sandboxID"] != "sbxconn1" || info["state"] != "running" {
		t.Fatalf("unexpected info: %s", rec.Body.String())
	}
	st, _ := state.LoadState("sbxconn1")
	if !st.Deadline.Equal(deadline) {
		t.Fatalf("bare connect moved the deadline: %v", st.Deadline)
	}

	// Connect with a timeout resets the deadline to now+timeout (seconds).
	beforeSet := time.Now().UTC()
	if rec = doCompat(t, e, http.MethodPost, "/sandboxes/sbxconn1/connect", "secret", `{"timeout":600}`, false); rec.Code != http.StatusOK {
		t.Fatalf("connect timeout: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	st, _ = state.LoadState("sbxconn1")
	want := beforeSet.Add(600 * time.Second)
	if st.Deadline.Before(want.Add(-5*time.Second)) || st.Deadline.After(want.Add(5*time.Second)) {
		t.Fatalf("connect timeout deadline = %v, want ~%v", st.Deadline, want)
	}

	// timeout=-1 means never: zero deadline.
	if rec = doCompat(t, e, http.MethodPost, "/sandboxes/sbxconn1/connect", "secret", `{"timeout":-1}`, false); rec.Code != http.StatusOK {
		t.Fatalf("connect never: expected 200, got %d", rec.Code)
	}
	st, _ = state.LoadState("sbxconn1")
	if !st.Deadline.IsZero() {
		t.Fatalf("timeout=-1 must clear the deadline, got %v", st.Deadline)
	}

	// Unknown sandbox is 404.
	if rec = doCompat(t, e, http.MethodPost, "/sandboxes/nope/connect", "secret", `{}`, false); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown sandbox: expected 404, got %d", rec.Code)
	}
}
