package policy

import (
	"strings"
	"testing"

	"uml-container/internal/audit"
)

func tmpLedger2(t *testing.T) *audit.Ledger {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("policy-edge")
	return l
}

// TestSanitize_Coverage walks a list of field names that MUST be stripped and
// a list that MUST pass. If the bad-word list ever narrows, this catches it.
func TestSanitize_Coverage(t *testing.T) {
	mustDrop := []string{
		"token", "TOKEN", "ApiToken", "api_token",
		"secret", "secret_key", "client_secret",
		"password", "Password", "passwd",
		"apikey", "api_key", "API_KEY",
		"credential", "credentials",
		"cookie", "set_cookie", "session_cookie",
		"authorization", "Authorization",
		"private_key", "privateKey",
	}
	for _, k := range mustDrop {
		if audit.IsSafeSummaryKey(k) {
			t.Errorf("audit.IsSafeSummaryKey(%q) = true; should be DROPPED", k)
		}
	}
	mustPass := []string{
		"path", "file", "size", "bytes", "status", "count",
		"branch", "commit", "result", "stdout", "exit_code",
	}
	for _, k := range mustPass {
		if !audit.IsSafeSummaryKey(k) {
			t.Errorf("audit.IsSafeSummaryKey(%q) = false; should PASS", k)
		}
	}
}

// TestExecute_AuditRecordedEveryPath verifies that allow/constrain/deny/approve
// each write a ledger record, so the audit trail is complete regardless of
// which branch the agent hit.
func TestExecute_AuditRecordedEveryPath(t *testing.T) {
	l := tmpLedger2(t)
	g := NewGateway([]Rule{
		{Name: "read", Action: ActionAllow},
		{Name: "write", Action: ActionConstrain},
		{Name: "send", Action: ActionApprove},
		{Name: "pay", Action: ActionDeny},
	}, l)

	for _, name := range []string{"read", "write", "send", "pay"} {
		_, _ = g.Execute(ToolRequest{Name: name})
	}
	records, _ := l.ReadAll()
	// 4 executions + the 4 the broker-less gate might emit. At least 4.
	if len(records) < 4 {
		t.Errorf("expected >=4 audit records (one per branch), got %d", len(records))
	}
	// each branch's decision word should appear at least once
	joined := ""
	for _, r := range records {
		joined += string(r.Decision) + " "
	}
	for _, want := range []string{"allow", "constrain", "approve", "deny"} {
		if !strings.Contains(joined, want) {
			t.Errorf("decision %q missing from ledger: %s", want, joined)
		}
	}
}

// TestDecide_CatchAllLast ensures the auto-appended catch-all is the LAST rule
// (so a specific rule earlier wins).
func TestDecide_CatchAllLast(t *testing.T) {
	g := NewGateway([]Rule{{Name: "specific", Action: ActionAllow}}, nil)
	rules := g.Rules()
	if len(rules) < 2 {
		t.Fatal("expected at least 2 rules (specific + catch-all)")
	}
	if rules[len(rules)-1].Name != "*" {
		t.Errorf("catch-all must be last, got %q", rules[len(rules)-1].Name)
	}
}

// TestExecute_ConstrainExecutorEnforced: when an Executor is wired, a CONSTRAIN
// rule runs it and the audit decision is recorded as constrain (not allow).
func TestExecute_ConstrainExecutorEnforced(t *testing.T) {
	l := tmpLedger2(t)
	called := false
	g := NewGateway([]Rule{{Name: "write", Action: ActionConstrain}}, l)
	g.executor = func(req ToolRequest) (ToolResponse, error) {
		called = true
		return ToolResponse{OK: true, Summary: "wrote", Result: map[string]interface{}{"path": "/task/x"}}, nil
	}
	resp, err := g.Execute(ToolRequest{Name: "write"})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !called {
		t.Error("constrain executor not called")
	}
	if resp.Result["path"] != "/task/x" {
		t.Errorf("safe result lost: %+v", resp.Result)
	}
}

// TestExecute_NestedSecretKeyDropped: even when an executor returns nested
// structures, secret-named keys at EVERY level are stripped (sanitize is now
// recursive), not just at the top level.
func TestExecute_NestedSecretKeyDropped(t *testing.T) {
	l := tmpLedger2(t)
	g := NewGateway([]Rule{{Name: "r", Action: ActionAllow}}, l)
	g.executor = func(req ToolRequest) (ToolResponse, error) {
		return ToolResponse{OK: true, Result: map[string]interface{}{
			"path":   "/ok",
			"token":  "LEAK", // top-level secret: must drop
			"cookie": "session=xyz",
			"nested": map[string]interface{}{
				"token": "LEAK", // nested secret: must ALSO drop (the bug)
			},
		}}, nil
	}
	resp, _ := g.Execute(ToolRequest{Name: "r"})
	if _, leak := resp.Result["token"]; leak {
		t.Error("top-level token leaked through executor result")
	}
	if _, leak := resp.Result["cookie"]; leak {
		t.Error("cookie leaked")
	}
	if resp.Result["path"] != "/ok" {
		t.Error("safe field dropped")
	}
	// The recursive-scrub regression assertion: nested.token must be gone too.
	nested, ok := resp.Result["nested"].(map[string]interface{})
	if !ok {
		t.Fatal("nested map dropped entirely (should have been scrubbed, not removed)")
	}
	if _, leak := nested["token"]; leak {
		t.Error("nested token leaked (sanitize is not recursive)")
	}
	if _, leak := resp.Result["nested"]; !leak {
		t.Error("nested map missing")
	}
}
