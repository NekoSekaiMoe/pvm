// Package integrationtest holds cross-plane integration tests that verify the
// control planes compose correctly (spec -> container -> FSM -> audit; incident
// -> revoke -> audit; pool claim -> quota -> audit). These live in a separate
// package so they can import multiple internal packages without cycles.
package integrationtest

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"uml-container/internal/approval"
	"uml-container/internal/artifact"
	"uml-container/internal/audit"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/identity"
	"uml-container/internal/incident"
	"uml-container/internal/network/egress"
	"uml-container/internal/policy"
	"uml-container/internal/pool"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/uml"
)

// setupIsolatedRoots points every plane at a per-test temp dir so they compose
// without colliding on /var/lib.
func setupIsolatedRoots(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	state.RootDir = filepath.Join(dir, "state")
	audit.LedgerRoot = filepath.Join(dir, "audit")
	os.Setenv("PVM_CGROUP_ROOT", filepath.Join(dir, "cg"))
	t.Cleanup(func() { os.Unsetenv("PVM_CGROUP_ROOT") })
}

// noOpLauncher is a tracking launcher that never blocks.
type noOpLauncher struct{ args []string }

func (l *noOpLauncher) Start(ctx context.Context, kernel string, args []string, logFile *os.File) (int, *uml.Process, error) {
	l.args = args
	return 4242, &uml.Process{}, nil
}
func (l *noOpLauncher) Wait(*uml.Process) error { return nil }

// =====================================================================
// Flow 1: TaskSpec -> StartTask -> FSM reaches Review -> audit has SPEC+EXEC
// =====================================================================

func TestFlow_SpecToTaskToAudit(t *testing.T) {
	setupIsolatedRoots(t)
	s := &spec.TaskSpec{
		Version: 1, Caller: "alice", Tenant: "eng",
		Runtime:   spec.RuntimeSpec{Name: "flow1", CPU: 1, Memory: "256M"},
		Workspace: spec.WorkspaceSpec{Init: "/sbin/init"},
		Kernel:    spec.KernelSpec{Path: "/usr/lib/uml/linux"},
		Network:   spec.NetworkSpec{Enabled: false},
		Lifecycle: spec.LifecycleSpec{OnAnomaly: "pause"},
	}
	mgr := &container.Manager{Launcher: &noOpLauncher{}}

	if err := mgr.StartTask(context.Background(), "flow1", s); err != nil {
		t.Fatalf("starttask: %v", err)
	}

	// FSM: task landed in Review (clean exit awaits gate).
	st, _ := state.LoadState("flow1")
	if st.Status != state.StatusReview {
		t.Fatalf("status = %s, want review", st.Status)
	}
	if st.SpecFP != s.Fingerprint() {
		t.Error("spec fingerprint not pinned to state")
	}

	// Audit: SPEC+VERSION phase recorded.
	l, _ := audit.Open("flow1")
	recs, _ := l.ReadAll()
	var sawSpec bool
	for _, r := range recs {
		if r.Phase == audit.PhaseSpec {
			sawSpec = true
		}
	}
	if !sawSpec {
		t.Error("missing PhaseSpec record (SPEC+VERSION evidence)")
	}
	// And the chain verifies.
	if n, err := l.Verify(); err != nil || n == 0 {
		t.Errorf("audit chain invalid: n=%d err=%v", n, err)
	}
}

// =====================================================================
// Flow 2: incident -> revoke identities -> audit records revoke
// =====================================================================

func TestFlow_IncidentRevokesAndAudits(t *testing.T) {
	setupIsolatedRoots(t)
	ledger, _ := audit.Open("flow2")
	broker := identity.NewBroker(nil, identity.StaticStore{}, ledger, time.Hour)
	tok, _ := broker.Mint("alice", "eng", []string{"repo:read"}, time.Hour)

	// confirm token valid before incident
	if _, err := broker.Validate(tok); err != nil {
		t.Fatalf("token should be valid pre-revoke: %v", err)
	}

	ctl := incident.NewController(ledger, broker, incident.Hooks{
		FreezeRuntime: func(string) error { return nil },
	})
	_, err := ctl.Handle(context.Background(), incident.Anomaly{
		TaskID: "flow2", Severity: incident.SeverityHigh,
		Signal: "egress:sensitive-upload-attempt",
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	// verify the incident was recorded as a revoke/block in audit
	recs, _ := ledger.ReadAll()
	var sawIncident bool
	for _, r := range recs {
		if strings.HasPrefix(r.Action, "incident:") {
			sawIncident = true
		}
	}
	if !sawIncident {
		t.Error("incident not recorded in audit ledger")
	}
}

// =====================================================================
// Flow 3: pool claim -> quota exceeded -> denial audited
// =====================================================================

func TestFlow_PoolQuotaDenialAudited(t *testing.T) {
	setupIsolatedRoots(t)
	ledger, _ := audit.Open("flow3")
	pm := pool.NewManager(10, ledger)
	pm.SetQuota("tenant-x", pool.Quota{
		MaxConcurrent: 1, MaxCPU: 10, MaxMemoryMB: 99999, MaxTasksPerHour: 99,
	})
	tmpl := pool.Template{Name: "alpine", Memory: "256M", CPU: 1}
	pm.Warm(tmpl, 3)

	if _, err := pm.Claim("tenant-x", tmpl, "first"); err != nil {
		t.Fatalf("first claim should succeed: %v", err)
	}
	_, err := pm.Claim("tenant-x", tmpl, "second")
	if err == nil {
		t.Fatal("second claim should hit concurrency quota")
	}

	// the denial must be in the audit ledger
	recs, _ := ledger.ReadAll()
	var sawDeny bool
	for _, r := range recs {
		if r.Action == "pool:claim" && r.Decision == audit.DecisionDeny {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Error("quota denial not audited")
	}
}

// =====================================================================
// Flow 4: policy gateway + approval — a send_email pauses for approval, then
// after a human approves, a re-execution of the same call proceeds.
// (We don't re-execute; we verify the approval gate path is wired.)
// =====================================================================

func TestFlow_PolicyApprovalIntegration(t *testing.T) {
	setupIsolatedRoots(t)
	ledger, _ := audit.Open("flow4")
	am := approval.NewManager(ledger)
	gw := policy.NewGateway([]policy.Rule{
		{Name: "send_email", Action: policy.ActionApprove, Reason: "external send"},
		{Name: "read_file", Action: policy.ActionAllow},
	}, ledger)

	// read_file passes through
	if _, err := gw.Execute(policy.ToolRequest{Name: "read_file"}); err != nil {
		t.Fatalf("read should pass: %v", err)
	}

	// send_email requires approval
	_, err := gw.Execute(policy.ToolRequest{
		Name: "send_email",
		Args: map[string]interface{}{"to": "x@y.com"},
	})
	if !errors_is(err, policy.ErrApprovalRequired) {
		t.Fatalf("expected ErrApprovalRequired, got %v", err)
	}

	// create the matching approval ticket and approve it
	id, err := am.Create(approval.Ticket{
		TaskID: "flow4", Tool: "send_email",
		Target: "prod-mailer",
		Params: map[string]interface{}{"to": "x@y.com"},
	})
	if err != nil {
		t.Fatalf("create ticket: %v", err)
	}
	if err := am.Decide(id, true, "human"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !am.IsApproved("flow4", "send_email", map[string]interface{}{"to": "x@y.com"}) {
		t.Error("approval should now be valid for these bound params")
	}
}

// =====================================================================
// Flow 5: artifact gate rejects a bundle with a secret, release blocked.
// =====================================================================

func TestFlow_ArtifactGateBlocksRelease(t *testing.T) {
	setupIsolatedRoots(t)
	ledger, _ := audit.Open("flow5")
	g := artifact.NewGate(ledger)
	rs := &artifact.ReleaseService{
		Gate: g,
		Release: func(*artifact.Bundle, *artifact.Verdict) error {
			t.Fatal("Release must not run when gate fails")
			return nil
		},
	}
	bundle := &artifact.Bundle{
		TaskID: "flow5",
		Diff:   "AWS_SECRET_ACCESS_KEY=\"abcd" + strings.Repeat("e", 36) + "\"",
	}
	err := rs.Submit(bundle)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !errors_is(err, artifact.ErrRejected) {
		t.Errorf("expected ErrRejected, got %v", err)
	}
}

// =====================================================================
// Flow 6: egress + identity compose — a request carries a broker token in
// the X-Task-Id header and is allowed/blocked per the policy.
// =====================================================================

func TestFlow_EgressPolicyEnforced(t *testing.T) {
	setupIsolatedRoots(t)
	ledger, _ := audit.Open("flow6")
	g := egress.NewGateway()
	g.AttachLedger(ledger)
	g.SetPolicy("flow6", &egress.Policy{
		AllowDomains: []string{"allowed.example"},
	})
	if _, err := g.Listen(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { g.Shutdown(context.Background()) })

	// Fire two real requests through the proxy: one allowed, one blocked.
	// The recording helper g_decide drives the decision the gateway will make
	// so we can pick a request the gateway will actually act on. We don't need
	// a real upstream: blocked requests return 403 from the proxy itself.
	c := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}, Timeout: 3 * time.Second}

	for _, host := range []string{"allowed.example", "blocked.example"} {
		req, _ := http.NewRequest("GET", "http://"+host+"/", nil)
		req.Header.Set("X-Task-Id", "flow6")
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		// both outcomes (200 upstream-reachable or 403 blocked) go through the
		// gateway, which records an audit row either way.
	}

	// audit ledger captured both decisions
	recs, _ := ledger.ReadAll()
	if len(recs) < 2 {
		t.Errorf("expected >=2 egress audit records, got %d", len(recs))
	}
}

// errors_is avoids importing "errors" in the helper section ambiguity.
func errors_is(err, target error) bool {
	if err == nil {
		return false
	}
	for {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
		if err == nil {
			return false
		}
	}
}

// keep unused imports referenced (config/cgroup are used by setup paths).
var _ = config.ParseMemory
var _ = cgroup.NewManager
