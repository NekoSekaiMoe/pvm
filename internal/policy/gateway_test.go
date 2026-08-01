package policy

import (
	"errors"
	"testing"

	"uml-container/internal/audit"
)

func tmpLedger(t *testing.T) *audit.Ledger {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("policy-test")
	return l
}

func TestDecide_SpecificWins(t *testing.T) {
	rules := []Rule{
		{Name: "read_file", Action: ActionAllow},
		{Name: "deploy", Action: ActionDeny, Reason: "prod protected"},
	}
	g := NewGateway(rules, tmpLedger(t))

	act, _, _ := g.Decide(ToolRequest{Name: "read_file"})
	if act != ActionAllow {
		t.Errorf("read_file should be allowed, got %s", act)
	}
	act, _, _ = g.Decide(ToolRequest{Name: "deploy"})
	if act != ActionDeny {
		t.Errorf("deploy should be denied, got %s", act)
	}
}

func TestDecide_DefaultDeny(t *testing.T) {
	g := NewGateway([]Rule{{Name: "read_file", Action: ActionAllow}}, tmpLedger(t))
	act, _, _ := g.Decide(ToolRequest{Name: "unknown_tool"})
	if act != ActionDeny {
		t.Errorf("unknown tool should default-deny, got %s", act)
	}
}

func TestExecute_DenyReturnsErr(t *testing.T) {
	g := NewGateway([]Rule{{Name: "pay", Action: ActionDeny, Reason: "no payments"}}, tmpLedger(t))
	_, err := g.Execute(ToolRequest{Name: "pay"})
	if !errors.Is(err, ErrDenied) {
		t.Errorf("expected ErrDenied, got %v", err)
	}
}

func TestExecute_ApproveReturnsApprovalErr(t *testing.T) {
	g := NewGateway([]Rule{{Name: "send_email", Action: ActionApprove, Reason: "external send"}}, tmpLedger(t))
	_, err := g.Execute(ToolRequest{Name: "send_email"})
	if !errors.Is(err, ErrApprovalRequired) {
		t.Errorf("expected ErrApprovalRequired, got %v", err)
	}
}

func TestExecute_AllowDryRun(t *testing.T) {
	g := NewGateway([]Rule{{Name: "read_file", Action: ActionAllow}}, tmpLedger(t))
	resp, err := g.Execute(ToolRequest{Name: "read_file"})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !resp.OK {
		t.Errorf("dry-run should return OK, got %+v", resp)
	}
}

func TestSanitize_StripsSecrets(t *testing.T) {
	r := ToolResponse{
		OK:      true,
		Summary: "wrote file",
		Result: map[string]interface{}{
			"path":     "/task/x.txt",
			"token":    "SUPERSECRET",
			"API_KEY":  "leak",
			"bytes":    42,
			"password": "hunter2",
		},
	}
	got := sanitize(r)
	if _, leak := got.Result["token"]; leak {
		t.Error("token leaked through sanitize")
	}
	if _, leak := got.Result["API_KEY"]; leak {
		t.Error("API_KEY leaked (case-insensitive check failed)")
	}
	if _, leak := got.Result["password"]; leak {
		t.Error("password leaked")
	}
	if v, ok := got.Result["path"]; !ok || v != "/task/x.txt" {
		t.Errorf("safe key 'path' lost or altered: %+v", got.Result)
	}
}

func TestCompileRules(t *testing.T) {
	raw := []struct{ Name, Action, Effect, Reason string }{
		{"read", "allow", "read", ""},
		{"write", "constrain", "write", "task branch only"},
		{"pay", "deny", "pay", "no payments"},
	}
	rules := CompileRules(raw)
	if len(rules) != 3 || rules[1].Action != ActionConstrain {
		t.Errorf("compile wrong: %+v", rules)
	}
	// verify case-insensitive
	rules = CompileRules([]struct{ Name, Action, Effect, Reason string }{{"x", "ALLOW", "", ""}})
	if rules[0].Action != ActionAllow {
		t.Errorf("case-insensitive action failed: %s", rules[0].Action)
	}
}

func TestStringContains(t *testing.T) {
	// Conservative posture: any key whose name contains a secret-like
	// substring is dropped, even if it's a false positive (e.g. 'keyboard').
	// This is intentional: deny-by-default on the Observation surface.
	if isSafeSummaryKey("keyboard") {
		t.Error("'keyboard' should be dropped (contains 'key'); conservative deny-by-default")
	}
	if isSafeSummaryKey("api_token") {
		t.Error("'api_token' should be dropped")
	}
	if !isSafeSummaryKey("path") {
		t.Error("'path' is safe and should pass")
	}
	if !isSafeSummaryKey("bytes") {
		t.Error("'bytes' is safe and should pass")
	}
}
