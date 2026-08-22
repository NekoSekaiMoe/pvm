package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"uml-container/internal/approval"
	"uml-container/internal/audit"
	"uml-container/internal/policy"
	"uml-container/internal/pool"
	"uml-container/internal/state"
)

// doJSON is a small helper to POST/GET JSON with the shared api secret.
func doJSON(t *testing.T, method, base, path string, body interface{}) (*http.Response, map[string]interface{}) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, r)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]interface{}
	_ = json.Unmarshal(data, &out)
	return resp, out
}

func resetPlanes(t *testing.T) {
	t.Helper()
	audit.LedgerRoot = t.TempDir()
	globalApprovals = approval.NewManager(nil)
	globalPool = pool.NewManager(16, nil)
}

// seedTask writes a task state.json in the configured RootDir (already a temp
// dir from bootServer).
func seedTask(t *testing.T, id string, status string) {
	t.Helper()
	st := &state.ContainerState{ID: id, Name: id, Status: state.Status(status)}
	if err := state.SaveState(id, st); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// --- /api/tasks/load-spec ---

func TestAPI_LoadSpec_FromContent(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)
	toml := `
version = 1
caller = "alice"
[runtime]
name = "t1"
cpu = 500
memory = "512M"
[workspace]
base_image = "alpine.img"
init = "/init.sh"
[kernel]
path = "./bin/linux"
`
	resp, out := doJSON(t, "POST", base, "/api/tasks/load-spec", map[string]string{"content": toml})
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%v", resp.StatusCode, out)
	}
	fp, _ := out["fingerprint"].(string)
	if fp == "" {
		t.Error("expected fingerprint")
	}
}

func TestAPI_LoadSpec_RejectBadTOML(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)
	resp, out := doJSON(t, "POST", base, "/api/tasks/load-spec", map[string]string{"content": "version = ["})
	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	if !strings.Contains(out["error"].(string), "parse") && !strings.Contains(out["error"].(string), "caller") {
		t.Errorf("expected parse/caller error, got %v", out["error"])
	}
}

// --- /api/tasks/:id/transition (FSM) ---

func TestAPI_Transition_ValidAndInvalid(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)
	// seed a task in Pending
	seedTask(t, "tk1", "pending")

	resp, out := doJSON(t, "POST", base, "/api/tasks/tk1/transition",
		map[string]string{"to": "provisioning", "actor": "controller", "reason": "go"})
	if resp.StatusCode != 200 {
		t.Fatalf("valid transition: status=%d body=%v", resp.StatusCode, out)
	}

	// invalid edge: pending can't jump straight to running (must provision first)
	resp, out = doJSON(t, "POST", base, "/api/tasks/tk1/transition",
		map[string]string{"to": "suspended", "actor": "controller"})
	if resp.StatusCode != 409 {
		t.Errorf("expected 409 conflict on invalid transition, got %d", resp.StatusCode)
	}
}

// --- /api/audit/:id + /verify ---

func TestAPI_Audit_VerifyChain(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)
	// write a couple of audit records directly
	l, _ := audit.Open("tk2")
	l.Append(audit.Record{Phase: audit.PhaseGoalAuth, Subject: "alice", Action: "auth", Decision: audit.DecisionAllow})
	l.Append(audit.Record{Phase: audit.PhaseExec, Subject: "alice", Action: "read", Decision: audit.DecisionAllow})

	resp, out := doJSON(t, "GET", base, "/api/audit/tk2/verify", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if out["valid"] != true {
		t.Errorf("expected valid chain, got %v", out)
	}
	if int(out["records"].(float64)) != 2 {
		t.Errorf("expected 2 records, got %v", out["records"])
	}
}

// --- /api/approvals ---

func TestAPI_Approvals_CreateDecide(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)

	resp, out := doJSON(t, "POST", base, "/api/approvals", map[string]interface{}{
		"task_id": "tk3", "tool": "send_email", "target": "prod",
		"params": map[string]interface{}{"to": "x@y.com"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("create: status=%d body=%v", resp.StatusCode, out)
	}
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatal("no ticket id")
	}

	// approve it
	resp, out = doJSON(t, "POST", base, "/api/approvals/"+id+"/decide", map[string]interface{}{
		"approved": true, "by": "alice",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("decide: status=%d", resp.StatusCode)
	}
	if out["state"] != "approved" {
		t.Errorf("expected approved state, got %v", out["state"])
	}
}

// --- /api/policy/:task ---

func TestAPI_Policy_List(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)
	gw := policy.NewGateway([]policy.Rule{
		{Name: "read_file", Action: policy.ActionAllow},
		{Name: "deploy", Action: policy.ActionDeny, Reason: "prod protected"},
	}, nil)
	RegisterPolicyGateway("tk4", gw)
	t.Cleanup(func() { UnregisterPolicyGateway("tk4") })

	// policy returns a bare JSON array, so parse it directly.
	req, _ := http.NewRequest("GET", base+"/api/policy/tk4", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var rules []policy.Rule
	json.NewDecoder(resp.Body).Decode(&rules)
	// 2 explicit + 1 auto-appended catch-all deny
	if len(rules) < 2 {
		t.Errorf("expected >=2 rules, got %d", len(rules))
	}
	if rules[0].Name != "read_file" || rules[0].Action != policy.ActionAllow {
		t.Errorf("first rule wrong: %+v", rules[0])
	}
}

// --- /api/pool/stats + /warm ---

func TestAPI_Pool_WarmAndStats(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)

	resp, out := doJSON(t, "POST", base, "/api/pool/warm", map[string]interface{}{
		"template": pool.Template{Name: "alpine", Memory: "256M", CPU: 1}, "n": 3,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("warm: status=%d body=%v", resp.StatusCode, out)
	}
	if int(out["created"].(float64)) != 3 {
		t.Errorf("expected 3 created, got %v", out["created"])
	}

	resp, out = doJSON(t, "GET", base, "/api/pool/stats", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("stats: %d", resp.StatusCode)
	}
	if int(out["ready"].(float64)) != 3 {
		t.Errorf("expected 3 ready, got %v", out["ready"])
	}
}

// --- /api/gate/verify ---

func TestAPI_Gate_RejectSecret(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)
	resp, out := doJSON(t, "POST", base, "/api/gate/verify", map[string]interface{}{
		"task_id": "tk5", "diff": "ghp_" + strings.Repeat("a", 36), "claimed_ok": true,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if out["passed"] == true {
		t.Error("gate should reject a diff containing a GitHub token")
	}
}

// --- empty-list JSON contract ---

// Nil Go slices marshal to JSON null; every list endpoint must emit [] so
// array-expecting clients (WebUI, E2B SDKs) don't crash on empty state.
// Regression test: state.ListAll, audit ReadAll, and approval.Pending all
// used to return nil when empty.
func TestAPI_EmptyListsAreArraysNotNull(t *testing.T) {
	base := bootServer(t)
	resetPlanes(t)

	for _, path := range []string{
		"/api/containers",
		"/api/tasks",
		"/api/approvals",
		"/api/audit/tk-empty",
	} {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: status=%d body=%s", path, resp.StatusCode, body)
		}
		if got := strings.TrimSpace(string(body)); got != "[]" {
			t.Errorf("GET %s: empty state must serialize as [], got %s", path, got)
		}
	}
}
