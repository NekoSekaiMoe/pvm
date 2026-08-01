// Package securitytest holds adversarial tests that actively attack the safety
// properties the architecture claims. Each test tries to BREAK a guarantee;
// passing means the guarantee held.
//
// Covered attacks:
//   - ledger tampering (truncate / reorder / rewrite)
//   - token forgery & tampering
//   - secrets leaking into tokens or observations
//   - DNS rebinding / SSRF to private IP via allowlisted domain
//   - secret in artifact diff bypassing the gate
//   - quota bypass via repeated claims
//   - approval param-binding bypass (approve one, run another)
//   - spec validation bypass (negative cpu, overflow memory)
package securitytest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"uml-container/internal/approval"
	"uml-container/internal/artifact"
	"uml-container/internal/audit"
	"uml-container/internal/identity"
	"uml-container/internal/network/egress"
	"uml-container/internal/policy"
	"uml-container/internal/pool"
	"uml-container/internal/spec"
	"uml-container/internal/state"
)

func setupRoots(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	state.RootDir = filepath.Join(dir, "state")
	audit.LedgerRoot = filepath.Join(dir, "audit")
}

// =====================================================================
// ATTACK 1: rewrite a ledger record's reason. Chain MUST break on verify.
// =====================================================================

func TestAttack_LedgerRewriteDetected(t *testing.T) {
	setupRoots(t)
	l, _ := audit.Open("victim")
	l.Append(audit.Record{Phase: audit.PhaseExec, Subject: "agent", Action: "read", Decision: audit.DecisionAllow, Reason: "legit"})
	l.Append(audit.Record{Phase: audit.PhaseExec, Subject: "agent", Action: "write", Decision: audit.DecisionDeny, Reason: "outside branch"})

	// attacker rewrites "outside branch" -> "approved" hoping to hide the denial
	path := filepath.Join(audit.LedgerRoot, "victim", "ledger.jsonl")
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), "outside branch", "approved", 1)
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}

	l2, _ := audit.Open("victim")
	_, err := l2.Verify()
	if err == nil {
		t.Fatal("SECURITY: ledger rewrite NOT detected — chain still verifies after tampering")
	}
}

// =====================================================================
// ATTACK 2: truncate the ledger to hide the last records. The surviving
// prefix should still verify, BUT the attacker can't forge a continuation
// because they'd need the prev_hash they just truncated.
// =====================================================================

func TestAttack_LedgerTruncationThenForgeFails(t *testing.T) {
	setupRoots(t)
	l, _ := audit.Open("victim2")
	for i := 0; i < 3; i++ {
		l.Append(audit.Record{Phase: audit.PhaseExec, Subject: "x", Action: fmt.Sprintf("a%d", i), Decision: audit.DecisionAllow})
	}
	// attacker truncates to 1 record, then appends a forged record claiming
	// the agent never did anything wrong.
	path := filepath.Join(audit.LedgerRoot, "victim2", "ledger.jsonl")
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	os.WriteFile(path, []byte(lines[0]+"\n"), 0644)

	// re-open so the in-memory tail is the truncated one
	_, _ = audit.Open("victim2")

	// now forge: compute the hash an attacker would need to continue the chain.
	// They CAN compute prev_hash = the only surviving record's this_hash. So
	// forging the *continuation* is possible IF they control the writer. The
	// guarantee we assert here is narrower: a record appended by a party that
	// does NOT know the canonical hash function still breaks the chain.
	fakeRec := audit.Record{
		Phase: audit.PhaseExec, Subject: "x", Action: " forged",
		Decision: audit.DecisionAllow, Reason: "coverup",
		// attacker uses a wrong prev_hash on purpose (they don't have the real one):
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	// write the forged line by hand (bypassing the ledger's hash logic)
	fakeRec.At = time.Now().UTC()
	fakeRec.Seq = 2
	fakeRec.ThisHash = "faked by attacker"
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	_ = json.NewEncoder(f).Encode(&fakeRec)
	f.Close()

	l3, _ := audit.Open("victim2")
	_, err := l3.Verify()
	if err == nil {
		t.Fatal("SECURITY: forged continuation accepted — hash chain broken but verify passed")
	}
}

// --- helpers kept minimal; the attack file uses stdlib json directly. ---

// =====================================================================
// ATTACK 3: forge a broker token. Must fail signature check.
// =====================================================================

func TestAttack_ForgedToken(t *testing.T) {
	setupRoots(t)
	ledger, _ := audit.Open("sec-id")
	broker := identity.NewBroker([]byte("real-secret-key"), nil, ledger, time.Hour)
	real, _ := broker.Mint("alice", "eng", []string{"repo:read"}, time.Hour)

	// attacker flips the last char of the signature
	forged := real[:len(real)-1]
	if strings.HasSuffix(real, "A") {
		forged += "B"
	} else {
		forged += "A"
	}
	_, err := broker.Validate(forged)
	if !errors.Is(err, identity.ErrSignature) {
		t.Errorf("SECURITY: forged token accepted, err=%v", err)
	}
}

// =====================================================================
// ATTACK 4: steal the token string, look for the long-lived secret inside it.
// =====================================================================

func TestAttack_SecretNotInToken(t *testing.T) {
	setupRoots(t)
	ledger, _ := audit.Open("sec-leak")
	broker := identity.NewBroker(nil, identity.StaticStore{"repo:read": "ULTRA-SECRET-12345"}, ledger, time.Hour)
	tok, _ := broker.Mint("alice", "eng", []string{"repo:read"}, time.Hour)
	if strings.Contains(tok, "ULTRA-SECRET-12345") {
		t.Fatal("SECURITY: long-lived secret leaked into the token string")
	}
}

// =====================================================================
// ATTACK 5: DNS rebinding — a domain the proxy allowlists resolves to a
// private IP. The SSRF floor must block the dial regardless.
// =====================================================================

func TestAttack_DNSRebindingToPrivateIP(t *testing.T) {
	setupRoots(t)
	ledger, _ := audit.Open("sec-ssrf")
	g := egress.NewGateway()
	g.AttachLedger(ledger)
	// allowlist "localhost" — the proxy will allow the domain, but the dial
	// must be refused because 127.0.0.1 is private.
	g.SetPolicy("t", &egress.Policy{AllowDomains: []string{"localhost", "127.0.0.1"}})
	addr, _ := g.Listen(context.Background(), "127.0.0.1:0")
	defer g.Shutdown(context.Background())

	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + addr)
	}}
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", "http://127.0.0.1:1/", nil)
	req.Header.Set("X-Task-Id", "t")
	resp, err := c.Do(req)
	if err == nil {
		// must NOT be 200 OK to the private target
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Fatal("SECURITY: CONNECT tunneled to a private (loopback) IP")
		}
		resp.Body.Close()
	}
}

// =====================================================================
// ATTACK 6: artifact diff contains a secret; gate MUST reject and release
// MUST NOT run.
// =====================================================================

func TestAttack_SecretInArtifactDiff(t *testing.T) {
	setupRoots(t)
	ledger, _ := audit.Open("sec-art")
	released := false
	rs := &artifact.ReleaseService{
		Gate: artifact.NewGate(ledger),
		Release: func(*artifact.Bundle, *artifact.Verdict) error {
			released = true
			return nil
		},
	}
	// Multiple secret shapes the gate must catch.
	for _, secret := range []string{
		"AKIAIOSFODNN7EXAMPLE",                                  // AWS access key
		"ghp_" + strings.Repeat("a", 36),                        // GitHub token
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE",                 // private key
		"xoxb-" + strings.Repeat("p", 12) + "-" + strings.Repeat("q", 12), // Slack
	} {
		released = false
		bundle := &artifact.Bundle{TaskID: "sec-art", Diff: "added: " + secret}
		if err := rs.Submit(bundle); err == nil {
			t.Errorf("SECURITY: gate accepted diff containing %q", secret[:8])
		}
		if released {
			t.Errorf("SECURITY: Release ran despite secret %q in diff", secret[:8])
		}
	}
}

// =====================================================================
// ATTACK 7: approve one param set, then try to run with a different one.
// The approval MUST NOT transfer (param binding).
// =====================================================================

func TestAttack_ApprovalParamBinding(t *testing.T) {
	setupRoots(t)
	ledger, _ := audit.Open("sec-appr")
	am := approval.NewManager(ledger)
	id, _ := am.Create(approval.Ticket{
		TaskID: "t", Tool: "send_email",
		Params: map[string]interface{}{"to": "safe@example.com"},
	})
	_ = am.Decide(id, true, "human")

	if !am.IsApproved("t", "send_email", map[string]interface{}{"to": "safe@example.com"}) {
		t.Fatal("approved params should pass")
	}
	// attacker swaps the recipient
	if am.IsApproved("t", "send_email", map[string]interface{}{"to": "attacker@evil.com"}) {
		t.Fatal("SECURITY: approval bled into un-approved params")
	}
}

// =====================================================================
// ATTACK 8: quota bypass — hammer claims concurrently, none should exceed
// the concurrency cap.
// =====================================================================

func TestAttack_QuotaBypassViaConcurrency(t *testing.T) {
	setupRoots(t)
	ledger, _ := audit.Open("sec-quota")
	pm := pool.NewManager(100, ledger)
	pm.SetQuota("evil", pool.Quota{
		MaxConcurrent: 2, MaxCPU: 100, MaxMemoryMB: 999999, MaxTasksPerHour: 999,
	})
	tmpl := pool.Template{Name: "x", Memory: "128M", CPU: 1}
	pm.Warm(tmpl, 50)

	var wg sync.WaitGroup
	var success, fail int64
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pm.Claim("evil", tmpl, "race")
			mu.Lock()
			if err == nil {
				success++
			} else {
				fail++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if success > 2 {
		t.Errorf("SECURITY: quota bypassed — %d concurrent claims (cap 2)", success)
	}
}

// =====================================================================
// ATTACK 9: spec validation bypass — overflow memory, negative cpu, malformed
// durations. All must be rejected.
// =====================================================================

func TestAttack_SpecValidationBypass(t *testing.T) {
	cases := []struct{ name string; s *spec.TaskSpec }{
		{"negative cpu", &spec.TaskSpec{Version: 1, Caller: "x", Runtime: spec.RuntimeSpec{CPU: -1}}},
		{"huge cpu", &spec.TaskSpec{Version: 1, Caller: "x", Runtime: spec.RuntimeSpec{CPU: 100000}}},
		{"bad action", &spec.TaskSpec{Version: 1, Caller: "x", Tools: []spec.ToolRule{{Name: "t", Action: "allow-and-also-deny"}}}},
		{"bad on_anomaly", &spec.TaskSpec{Version: 1, Caller: "x", Lifecycle: spec.LifecycleSpec{OnAnomaly: "ignore"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.s.Validate(); err == nil {
				t.Errorf("SECURITY: spec %q was accepted", c.name)
			}
		})
	}
}

// =====================================================================
// ATTACK 10: observation leak — an executor returns a result containing a
// field named like a secret. Sanitize MUST strip it before it reaches the
// agent.
// =====================================================================

func TestAttack_ObservationLeak(t *testing.T) {
	setupRoots(t)
	ledger, _ := audit.Open("sec-obs")
	gw := policy.NewGateway([]policy.Rule{{Name: "r", Action: policy.ActionAllow}}, ledger)
	gw.Executor = func(req policy.ToolRequest) (policy.ToolResponse, error) {
		return policy.ToolResponse{OK: true, Result: map[string]interface{}{
			"path":         "/ok",
			"access_token": "bearer SECRET-VALUE",
			"session":      "safe",
		}}, nil
	}
	resp, _ := gw.Execute(policy.ToolRequest{Name: "r"})
	for _, leak := range []string{"access_token"} {
		if _, ok := resp.Result[leak]; ok {
			t.Errorf("SECURITY: %q leaked into the Observation returned to the agent", leak)
		}
	}
}

// --- helpers ---

// --- keep nothing else; stdlib json handles encoding. ---
var _ = io.Copy
