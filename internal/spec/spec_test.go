package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "spec.toml")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

const minimalValid = `
version = 1
caller = "alice"
tenant = "eng"

[runtime]
name = "t1"
cpu = 500
memory = "512M"

[workspace]
base_image = "alpine.img"
init = "/init.sh"

[kernel]
path = "./bin/linux"
virtio = true
use_vhost_blk = true

[network]
enabled = true
bridge = "br0"
gateway_ip = "10.0.0.1/24"
egress_allow_domains = ["github.com", "registry.npmjs.org"]

[[tools]]
name = "read_file"
action = "allow"

[[tools]]
name = "deploy"
action = "deny"
reason = "production denied by default"

[budget]
max_wall_time = "15m"
max_tokens = 100000

[approval]
required_for = ["send", "delete"]

[artifacts]
declared = ["out/diff.patch"]
require_tests_passed = true
block_secrets = true

[lifecycle]
max_retries = 2
on_anomaly = "pause"
ttl = "1h"
`

func TestLoadFile_Valid(t *testing.T) {
	p := writeTemp(t, minimalValid)
	s, err := LoadFile(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if s.Caller != "alice" || s.Tenant != "eng" {
		t.Errorf("identity parse wrong: %+v", s)
	}
	if s.Runtime.CPU != 500 || s.Runtime.Memory != "512M" {
		t.Errorf("runtime parse wrong: %+v", s.Runtime)
	}
	if len(s.Network.EgressAllowDomains) != 2 {
		t.Errorf("egress allow list wrong: %v", s.Network.EgressAllowDomains)
	}
	if len(s.Tools) != 2 || s.Tools[1].Action != "deny" {
		t.Errorf("tools parse wrong: %v", s.Tools)
	}
	if !s.Artifacts.RequireTestsPassed {
		t.Errorf("artifacts flag lost")
	}
}

func TestLoadFile_RejectUnknownKey(t *testing.T) {
	bad := strings.Replace(minimalValid, `[runtime]`, "[runtime]\nbogus_field = true\n", 1)
	p := writeTemp(t, bad)
	_, err := LoadFile(p)
	if err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("expected unknown-key error, got: %v", err)
	}
}

func TestValidate_MissingCaller(t *testing.T) {
	s := &TaskSpec{Version: 1} // no caller
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "caller is required") {
		t.Fatalf("expected caller-required error, got: %v", err)
	}
}

func TestValidate_BadToolAction(t *testing.T) {
	s := &TaskSpec{Version: 1, Caller: "x", Tools: []ToolRule{{Name: "t", Action: "explode"}}}
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "action") {
		t.Fatalf("expected bad-action error, got: %v", err)
	}
}

func TestValidate_BadDuration(t *testing.T) {
	s := &TaskSpec{Version: 1, Caller: "x", Budget: BudgetSpec{MaxWallTime: "not-a-duration"}}
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "max_wall_time") {
		t.Fatalf("expected duration error, got: %v", err)
	}
}

func TestFingerprint_Stable(t *testing.T) {
	p := writeTemp(t, minimalValid)
	s1, _ := LoadFile(p)
	s2, _ := LoadFile(p)
	if s1.Fingerprint() != s2.Fingerprint() {
		t.Fatal("fingerprint not stable across loads of identical specs")
	}
	// and changes when the contract changes
	s1.Runtime.CPU = 999
	if s1.Fingerprint() == s2.Fingerprint() {
		t.Fatal("fingerprint should change when cpu changes")
	}
}

func TestValidate_DefaultsOnAnomaly(t *testing.T) {
	s := &TaskSpec{Version: 1, Caller: "x"}
	_ = s.Validate()
	if s.Lifecycle.OnAnomaly != "pause" {
		t.Errorf("on_anomaly default not applied: %s", s.Lifecycle.OnAnomaly)
	}
}

// TestValidate_AppliesDefaults ensures the DefaultXxx constants actually get
// filled in (they used to be dead code). Validate MUST populate the omitted
// budget/lifecycle/identity/approval fields so downstream consumers don't see
// empty strings.
func TestValidate_AppliesDefaults(t *testing.T) {
	s := &TaskSpec{Version: 1, Caller: "x"}
	if err := s.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if s.Budget.MaxWallTime != DefaultWallTimeout.String() {
		t.Errorf("max_wall_time default not applied: %q", s.Budget.MaxWallTime)
	}
	if s.Identity.TTL != DefaultTokenTTL.String() {
		t.Errorf("identity.ttl default not applied: %q", s.Identity.TTL)
	}
	if s.Lifecycle.TTL != DefaultLifecycleTTL.String() {
		t.Errorf("lifecycle.ttl default not applied: %q", s.Lifecycle.TTL)
	}
	if s.Lifecycle.MaxRetries != DefaultMaxRetries {
		t.Errorf("lifecycle.max_retries default not applied: %d", s.Lifecycle.MaxRetries)
	}
	if s.Approval.Timeout != DefaultApprovalTimeout.String() {
		t.Errorf("approval.timeout default not applied: %q", s.Approval.Timeout)
	}
}

// TestValidate_RejectsNegativeMemory: parseMem accepts "%d" so "-512M" parses
// to -512. Validate MUST reject negative memory at the spec layer so it can't
// reach the cgroup/CoW startup path.
func TestValidate_RejectsNegativeMemory(t *testing.T) {
	s := &TaskSpec{Version: 1, Caller: "x", Runtime: RuntimeSpec{Memory: "-512M"}}
	err := s.Validate()
	if err == nil {
		t.Fatal("expected error for negative memory, got nil")
	}
}

// TestFingerprint_CoversControlFields verifies that changing ANY control-plane
// field the fingerprint claims to bind changes the digest. Pre-fix, the
// fingerprint only covered a hand-picked subset and silently ignored
// Identity.Scope, Network.Bridge/GatewayIP/TAP/MaxRequestBodyBytes/QoSRate,
// Kernel.*, Lifecycle.Paused/MaxRetries/TTL, Approval.Notify/Timeout, etc.
func TestFingerprint_CoversControlFields(t *testing.T) {
	base := &TaskSpec{Version: 1, Caller: "x", Tenant: "t"}
	_ = base.Validate()
	h0 := base.Fingerprint()

	// Each variant is named for the control field it mutates, so a failure
	// points directly at the field whose binding regressed instead of an index.
	variants := []struct {
		name string
		spec *TaskSpec
	}{
		{"identity.scope", &TaskSpec{Version: 1, Caller: "x", Tenant: "t", Identity: Identity{Scope: []string{"repo:read"}}}},
		{"network.bridge", &TaskSpec{Version: 1, Caller: "x", Tenant: "t", Network: NetworkSpec{Bridge: "br9"}}},
		{"network.qos_rate", &TaskSpec{Version: 1, Caller: "x", Tenant: "t", Network: NetworkSpec{QoSRate: "10mbit"}}},
		{"kernel.path", &TaskSpec{Version: 1, Caller: "x", Tenant: "t", Kernel: KernelSpec{Path: "./other/linux"}}},
		{"lifecycle.max_retries", &TaskSpec{Version: 1, Caller: "x", Tenant: "t", Lifecycle: LifecycleSpec{MaxRetries: 9}}},
		{"approval.notify", &TaskSpec{Version: 1, Caller: "x", Tenant: "t", Approval: ApprovalSpec{Notify: "webhook"}}},
		{"workspace.overlay", &TaskSpec{Version: 1, Caller: "x", Tenant: "t", Workspace: WorkspaceSpec{Overlay: "x.qcow2"}}},
	}
	for _, v := range variants {
		v := v
		t.Run(v.name, func(t *testing.T) {
			_ = v.spec.Validate()
			if v.spec.Fingerprint() == h0 {
				t.Errorf("changing %s produced the same fingerprint as base (control field not bound)", v.name)
			}
		})
	}
}
