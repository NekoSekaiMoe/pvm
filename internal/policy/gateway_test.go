package policy

import (
	"errors"
	"strings"
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
	if audit.IsSafeSummaryKey("keyboard") {
		t.Error("'keyboard' should be dropped (contains 'key'); conservative deny-by-default")
	}
	if audit.IsSafeSummaryKey("api_token") {
		t.Error("'api_token' should be dropped")
	}
	if !audit.IsSafeSummaryKey("path") {
		t.Error("'path' is safe and should pass")
	}
	if !audit.IsSafeSummaryKey("bytes") {
		t.Error("'bytes' is safe and should pass")
	}
}

// TestDecide_EffectGatesMatch covers the PAY/PROD default-deny guarantee
// (plan.md §6.2): a rule authorizing a tool only for read must NOT satisfy a
// request with effect="pay". Before the fix, Decide ignored Effect entirely;
// a later fix only handled the case where BOTH rule and request carried an
// Effect, so an effect-less request still matched a scoped rule.
func TestDecide_EffectGatesMatch(t *testing.T) {
	g := NewGateway([]Rule{
		{Name: "git", Action: ActionAllow, Effect: "read"},
		{Name: "git", Action: ActionDeny, Effect: "pay"}, // explicit deny for pay
	}, nil)
	// read effect -> matches the allow rule.
	if act, _, _ := g.Decide(ToolRequest{Name: "git", Effect: "read"}); act != ActionAllow {
		t.Errorf("read effect: expected allow, got %s", act)
	}
	// pay effect -> the read-scoped rule must NOT match; we fall through to the
	// pay-scoped deny rule (then the catch-all). Either way, NOT allow.
	act, _, _ := g.Decide(ToolRequest{Name: "git", Effect: "pay"})
	if act == ActionAllow {
		t.Errorf("pay effect: rule {Effect:read} satisfied a pay request (effect ignored)")
	}
	// EMPTY request Effect must NOT satisfy a scoped allow rule either: it
	// falls through to the pay-scoped deny (or the catch-all), never allow.
	// This is the regression the second fix closed.
	actEmpty, _, _ := g.Decide(ToolRequest{Name: "git"})
	if actEmpty == ActionAllow {
		t.Errorf("empty effect: scoped allow rule {Effect:read} satisfied an effect-less request")
	}
}

// TestSanitize_RecursivelyDropsNestedSecrets ensures sanitize walks into
// nested maps/slices so a token buried one level down is still stripped.
func TestSanitize_RecursivelyDropsNestedSecrets(t *testing.T) {
	in := ToolResponse{Result: map[string]interface{}{
		"path": "/ok",
		"meta": map[string]interface{}{
			"token":   "LEAK",
			"headers": map[string]interface{}{"Authorization": "Bearer x"},
		},
		"items": []interface{}{
			map[string]interface{}{"password": "p"},
			map[string]interface{}{"size": 1},
		},
	}}
	out := sanitize(in)
	top := out.Result
	if top == nil {
		t.Fatalf("sanitize dropped the whole Result map")
	}
	if _, leak := top["token"]; leak {
		t.Error("top-level token survived")
	}
	meta, ok := top["meta"].(map[string]interface{})
	if !ok {
		t.Fatalf("meta is not a map after sanitize: %T", top["meta"])
	}
	if _, leak := meta["token"]; leak {
		t.Error("nested map token survived (sanitize is not recursive)")
	}
	headers, ok := meta["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers is not a map after sanitize: %T", meta["headers"])
	}
	if _, leak := headers["Authorization"]; leak {
		t.Error("doubly-nested Authorization survived (sanitize is not recursive)")
	}
	items, ok := top["items"].([]interface{})
	if !ok || len(items) != 2 {
		t.Fatalf("items missing or wrong length after sanitize: %v", top["items"])
	}
	first, ok := items[0].(map[string]interface{})
	if !ok {
		t.Fatalf("items[0] is not a map after sanitize: %T", items[0])
	}
	if _, leak := first["password"]; leak {
		t.Error("nested slice element password survived")
	}
	second, ok := items[1].(map[string]interface{})
	if !ok {
		t.Fatalf("items[1] is not a map after sanitize: %T", items[1])
	}
	// JSON decoding produces float64 for numbers, but this test builds the
	// map from a Go int literal, so accept any numeric kind with value 1.
	switch s := second["size"].(type) {
	case float64:
		if s != 1 {
			t.Errorf("safe nested field 'size' altered: %v", second["size"])
		}
	case int:
		if s != 1 {
			t.Errorf("safe nested field 'size' altered: %v", second["size"])
		}
	default:
		t.Errorf("safe nested field 'size' was dropped or wrong type: %T %v", second["size"], second["size"])
	}
}

// TestSanitize_RedactsSummaryProse verifies a token echoed into Summary/Reason
// prose gets masked, not just struct keys.
func TestSanitize_RedactsSummaryProse(t *testing.T) {
	in := ToolResponse{
		Summary: "pushed with ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd",
		Reason:  "auth: Bearer abcdef0123456789abcdef0123456789",
	}
	out := sanitize(in)
	if strings.Contains(out.Summary, "ghp_") {
		t.Errorf("github token not redacted in summary: %s", out.Summary)
	}
	if strings.Contains(out.Reason, "Bearer abcdef") {
		t.Errorf("bearer token not redacted in reason: %s", out.Reason)
	}
}
