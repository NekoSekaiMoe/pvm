package spec

import (
	"strings"
	"testing"
)

// matrixNegatives covers every Validate() failure mode with a focused case.
// Each case mutates a known-good spec to introduce exactly one defect, so a
// regression that weakens any check is caught.
func baseValid() *TaskSpec {
	s := &TaskSpec{
		Version: 1, Caller: "alice",
		Runtime:  RuntimeSpec{CPU: 500, Memory: "512M"},
		Kernel:   KernelSpec{Path: "./bin/linux"},
		Network:  NetworkSpec{Enabled: true, GatewayIP: "10.0.0.1/24"},
		Identity: Identity{TTL: "15m"},
		Budget:   BudgetSpec{MaxWallTime: "30m"},
		Lifecycle: LifecycleSpec{OnAnomaly: "pause", TTL: "1h"},
		Approval: ApprovalSpec{Timeout: "5m"},
	}
	return s
}

func TestValidateMatrix(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*TaskSpec)
		wantSubstr string
	}{
		{"missing caller", func(s *TaskSpec) { s.Caller = "" }, "caller is required"},
		{"cpu negative", func(s *TaskSpec) { s.Runtime.CPU = -1 }, "cpu must be >= 0"},
		{"cpu too big", func(s *TaskSpec) { s.Runtime.CPU = 5000 }, "cpu must be <= 1024"},
		{"bad memory unit", func(s *TaskSpec) { s.Runtime.Memory = "5PB" }, "unsupported memory unit"},
		{"bad memory format", func(s *TaskSpec) { s.Runtime.Memory = "abc" }, "invalid memory"},
		{"bad identity ttl", func(s *TaskSpec) { s.Identity.TTL = "forever" }, "identity.ttl"},
		{"bad tool action", func(s *TaskSpec) {
			s.Tools = []ToolRule{{Name: "x", Action: "kaboom"}}
		}, "action"},
		{"bad budget duration", func(s *TaskSpec) { s.Budget.MaxWallTime = "two-minutes" }, "max_wall_time"},
		{"bad lifecycle ttl", func(s *TaskSpec) { s.Lifecycle.TTL = "never" }, "lifecycle.ttl"},
		{"bad on_anomaly", func(s *TaskSpec) { s.Lifecycle.OnAnomaly = "pray" }, "on_anomaly"},
		{"bad approval timeout", func(s *TaskSpec) { s.Approval.Timeout = "soon" }, "approval.timeout"},
		{"version mismatch", func(s *TaskSpec) { s.Version = 999 }, "version mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := baseValid()
			c.mutate(s)
			err := s.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantSubstr)
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("expected error containing %q, got: %v", c.wantSubstr, err)
			}
		})
	}
}

func TestValidate_AcceptsEmptyMemory(t *testing.T) {
	// Empty memory is allowed (means "use runtime default"); only malformed
	// non-empty strings should fail. This guards against over-strict validation.
	s := baseValid()
	s.Runtime.Memory = ""
	if err := s.Validate(); err != nil {
		t.Errorf("empty memory should be accepted, got: %v", err)
	}
}

func TestLoadString_AllKeySections(t *testing.T) {
	// LoadString must parse every section we documented in uml/agentpvm.toml;
	// a missing section would silently zero a control plane.
	toml := `
version = 1
caller = "alice"
tenant = "eng"

[runtime]
name = "t"
cpu = 1000
memory = "1G"

[workspace]
base_image = "alpine.img"
init = "/init.sh"

[kernel]
path = "./bin/linux"
virtio = true
use_vhost_blk = true

[network]
enabled = true
egress_allow_domains = ["a.com", "*.b.com"]
egress_block_domains = ["evil.com"]
max_request_body_bytes = 1024

[[tools]]
name = "read"
action = "allow"

[[tools]]
name = "deploy"
action = "deny"

[budget]
max_wall_time = "20m"
max_tokens = 5000

[approval]
required_for = ["send"]
timeout = "3m"

[artifacts]
declared = ["out/d.patch"]
require_tests_passed = true
block_secrets = true

[lifecycle]
on_anomaly = "terminate"
ttl = "30m"
max_retries = 3
`
	s, err := LoadString(toml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	checks := []struct{ name string; got, want interface{} }{
		{"tenant", s.Tenant, "eng"},
		{"virtio", s.Kernel.Virtio, true},
		{"vhost_blk", s.Kernel.UseVhostBlk, true},
		{"allow domains count", len(s.Network.EgressAllowDomains), 2},
		{"block domain", s.Network.EgressBlockDomains[0], "evil.com"},
		{"max_body", s.Network.MaxRequestBodyBytes, int64(1024)},
		{"tools count", len(s.Tools), 2},
		{"max_tokens", s.Budget.MaxTokens, 5000},
		{"approval required", s.Approval.RequiredFor[0], "send"},
		{"artifact declared", s.Artifacts.Declared[0], "out/d.patch"},
		{"block_secrets", s.Artifacts.BlockSecrets, true},
		{"on_anomaly", s.Lifecycle.OnAnomaly, "terminate"},
		{"max_retries", s.Lifecycle.MaxRetries, 3},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadString_RejectsUndecodedKeys(t *testing.T) {
	bad := `
version = 1
caller = "alice"
[typo_section]
fake = true
`
	_, err := LoadString(bad)
	if err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("expected unknown-keys error, got: %v", err)
	}
}

func TestFingerprint_DistinguishesContracts(t *testing.T) {
	// Two specs differing in only the caller must fingerprint differently —
	// identity is part of the contract, so the "WHO" changes the hash.
	s1 := baseValid()
	s2 := baseValid()
	s2.Caller = "bob"
	if s1.Fingerprint() == s2.Fingerprint() {
		t.Error("fingerprint must change when caller changes")
	}
}
