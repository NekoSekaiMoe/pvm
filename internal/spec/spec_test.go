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

func TestValidate_GuestIP(t *testing.T) {
	base := func() *TaskSpec { return &TaskSpec{Version: 1, Caller: "x"} }

	// Valid: override inside the gateway subnet.
	s := base()
	s.Network = NetworkSpec{Enabled: true, GatewayIP: "10.0.0.1/24", GuestIP: "10.0.0.50"}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid guest_ip rejected: %v", err)
	}
	// Valid without a gateway CIDR (subnet check deferred to the IPAM).
	s = base()
	s.Network = NetworkSpec{Enabled: true, GuestIP: "10.0.0.50"}
	if err := s.Validate(); err != nil {
		t.Fatalf("guest_ip without gateway rejected: %v", err)
	}

	cases := []struct {
		name         string
		gw, guest    string
		wantFragment string
	}{
		{"malformed", "10.0.0.1/24", "10.0.0.x", "not a valid IPv4"},
		{"ipv6", "10.0.0.1/24", "2001:db8::1", "not a valid IPv4"},
		{"outside subnet", "10.0.0.1/24", "10.0.9.5", "outside the bridge subnet"},
		{"gateway collision", "10.0.0.1/24", "10.0.0.1", "collides with the gateway"},
		{"bad gateway cidr", "bogus", "10.0.0.5", "not a valid CIDR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			s.Network = NetworkSpec{Enabled: true, GatewayIP: tc.gw, GuestIP: tc.guest}
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("want error containing %q, got: %v", tc.wantFragment, err)
			}
		})
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

// TestSecurityDefaultsMaterialized covers the toml.MetaData-based defaulting:
// host-enforcement toggles default to true ONLY when the key is absent — a
// plain bool zero value cannot distinguish "unset" from "explicit false", so
// without this a spec omitting [security] would silently launch without
// seccomp/Landlock enforcement (container.StartTask consumes these fields
// verbatim for jail.CheckSecurity / SetupJail).
func TestSecurityDefaultsMaterialized(t *testing.T) {
	const secExplicitFalse = `
[security]
enforce_host_seccomp = false
enforce_landlock     = false
`
	const secExplicitTrue = `
[security]
enforce_host_seccomp = true
enforce_landlock     = true
`
	cases := []struct {
		name           string
		extra          string
		wantSeccomp    bool
		wantLandlock   bool
		wantInsecureDg bool
	}{
		{"absent keys default true", "", true, true, false},
		{"explicit false honored", secExplicitFalse, false, false, false},
		{"explicit true honored", secExplicitTrue, true, true, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Cover both entry points: the file loader and the /api/tasks/load-spec
			// in-memory loader must agree.
			viaStr, err := LoadString(minimalValid + tc.extra)
			if err != nil {
				t.Fatalf("LoadString: %v", err)
			}
			viaFile, err := LoadFile(writeTemp(t, minimalValid+tc.extra))
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			for _, s := range []*TaskSpec{viaStr, viaFile} {
				if s.Security.EnforceHostSeccomp != tc.wantSeccomp {
					t.Errorf("EnforceHostSeccomp = %v, want %v", s.Security.EnforceHostSeccomp, tc.wantSeccomp)
				}
				if s.Security.EnforceLandlock != tc.wantLandlock {
					t.Errorf("EnforceLandlock = %v, want %v", s.Security.EnforceLandlock, tc.wantLandlock)
				}
				if s.Security.AllowInsecureDegraded != tc.wantInsecureDg {
					t.Errorf("AllowInsecureDegraded = %v, want %v (fail-closed default)",
						s.Security.AllowInsecureDegraded, tc.wantInsecureDg)
				}
			}
		})
	}
}

// TestValidate_DNSLearn pins the P1-B network.dns_learn_* contract: defaults
// are filled, durations/upstreams are validated regardless of the enable
// flag (config errors surface early), and the loader accepts the keys
// (md.Undecoded rejects unknown keys, so a missing struct field would fail).
func TestValidate_DNSLearn(t *testing.T) {
	// Defaults filled on a bare spec.
	s := &TaskSpec{Version: 1, Caller: "x"}
	if err := s.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if s.Network.LearnTTL != DefaultLearnTTL.String() {
		t.Errorf("learn_ttl default = %q, want %q", s.Network.LearnTTL, DefaultLearnTTL)
	}
	if s.Network.MaxLearnedEntries != DefaultMaxLearnedEntries {
		t.Errorf("max_learned_entries default = %d, want %d",
			s.Network.MaxLearnedEntries, DefaultMaxLearnedEntries)
	}

	bad := []struct {
		name, ttl, upstream string
		max                 int
		wantFragment        string
	}{
		{"bad ttl", "not-a-duration", "", 0, "learn_ttl"},
		{"zero ttl", "0s", "", 0, "learn_ttl"},
		{"negative ttl", "-5s", "", 0, "learn_ttl"},
		{"hostname upstream", "", "dns.google", 0, "dns_upstream"},
		{"bad port", "", "1.1.1.1:notaport", 0, "dns_upstream"},
		{"port range", "", "1.1.1.1:70000", 0, "dns_upstream"},
		{"negative max", "", "", -1, "max_learned_entries"},
		{"absurd max", "", "", MaxLearnedEntriesLimit + 1, "max_learned_entries"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			s := &TaskSpec{Version: 1, Caller: "x", Network: NetworkSpec{
				LearnTTL: tc.ttl, DNSUpstream: tc.upstream, MaxLearnedEntries: tc.max,
			}}
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("want error containing %q, got: %v", tc.wantFragment, err)
			}
		})
	}

	// Valid forms, including bare-IP upstream.
	s = &TaskSpec{Version: 1, Caller: "x", Network: NetworkSpec{
		DNSLearnEnabled: true, LearnTTL: "30s", DNSUpstream: "1.1.1.1", MaxLearnedEntries: 64,
	}}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid dns-learn spec rejected: %v", err)
	}

	// TOML round-trip: the loader must accept all four keys.
	s, err := LoadString("version = 1\ncaller = \"alice\"\n[network]\n" +
		"enabled = true\ndns_learn_enabled = true\nlearn_ttl = \"1s\"\n" +
		"dns_upstream = \"127.0.0.1:5353\"\nmax_learned_entries = 32\n")
	if err != nil {
		t.Fatalf("LoadString with dns_learn keys: %v", err)
	}
	if !s.Network.DNSLearnEnabled || s.Network.LearnTTL != "1s" ||
		s.Network.DNSUpstream != "127.0.0.1:5353" || s.Network.MaxLearnedEntries != 32 {
		t.Errorf("TOML round-trip mismatch: %+v", s.Network)
	}
}

func TestValidate_Dataplane(t *testing.T) {
	base := func() *TaskSpec { return &TaskSpec{Version: 1, Caller: "x"} }

	// Empty fills the historical default (bridge) and stays valid.
	s := base()
	if err := s.Validate(); err != nil {
		t.Fatalf("default dataplane rejected: %v", err)
	}
	if s.Network.Dataplane != DataplaneBridge {
		t.Fatalf("default dataplane = %q, want %q", s.Network.Dataplane, DataplaneBridge)
	}

	// "tc" is accepted.
	s = base()
	s.Network = NetworkSpec{Enabled: true, Dataplane: DataplaneTC}
	if err := s.Validate(); err != nil {
		t.Fatalf("dataplane=tc rejected: %v", err)
	}

	// Unknown values are config errors, never silently ignored.
	s = base()
	s.Network = NetworkSpec{Enabled: true, Dataplane: "ebpf-only"}
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), `network.dataplane "ebpf-only"`) {
		t.Fatalf("invalid dataplane not rejected with the field name: %v", err)
	}

	// tc mode IGNORES bridge/gateway_ip/guest_ip: an out-of-subnet or
	// malformed-for-bridge guest_ip must not trip the bridge-only
	// cross-checks (the fixed link-local addressing replaces them).
	s = base()
	s.Network = NetworkSpec{Enabled: true, Dataplane: "tc", GatewayIP: "10.0.0.1/24", GuestIP: "10.9.9.9"}
	if err := s.Validate(); err != nil {
		t.Fatalf("tc mode must ignore guest_ip/gateway_ip cross-checks: %v", err)
	}

	// Regression guard: bridge mode still enforces the subnet check.
	s = base()
	s.Network = NetworkSpec{Enabled: true, Dataplane: "bridge", GatewayIP: "10.0.0.1/24", GuestIP: "10.9.9.9"}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "outside the bridge subnet") {
		t.Fatalf("bridge mode lost the guest_ip subnet check: %v", err)
	}
}

func TestLoadFile_DataplaneTOML(t *testing.T) {
	// The TOML surface rejects unknown keys, so the new field must decode.
	doc := `
version = 1
caller = "alice"
[runtime]
name = "tc-task"
[workspace]
base_image = "alpine.img"
init = "/init.sh"
[network]
enabled = true
dataplane = "tc"
`
	s, err := LoadFile(writeTemp(t, doc))
	if err != nil {
		t.Fatalf("dataplane=tc TOML rejected: %v", err)
	}
	if s.Network.Dataplane != DataplaneTC {
		t.Fatalf("dataplane = %q, want tc", s.Network.Dataplane)
	}

	// Invalid value rejected at load.
	bad := strings.Replace(doc, `dataplane = "tc"`, `dataplane = "bogus"`, 1)
	if _, err := LoadFile(writeTemp(t, bad)); err == nil || !strings.Contains(err.Error(), "dataplane") {
		t.Fatalf("dataplane=bogus not rejected at load: %v", err)
	}
}

func TestValidateHostPathField(t *testing.T) {
	base := func() *TaskSpec {
		return &TaskSpec{Version: 1, Caller: "x"}
	}
	s := base()
	s.Volumes = []VolumeMount{{Name: "v", Path: "/w", HostPath: "/srv/shared/x"}}
	if err := s.Validate(); err != nil {
		t.Fatalf("absolute clean host_path must validate: %v", err)
	}
	s = base()
	s.Volumes = []VolumeMount{{Name: "v", Path: "/w", HostPath: "relative/x"}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "host_path") {
		t.Fatalf("relative host_path must fail, got %v", err)
	}
	s = base()
	s.Volumes = []VolumeMount{{Name: "v", Path: "/w", HostPath: "/has space"}}
	if err := s.Validate(); err == nil {
		t.Fatal("host_path with whitespace must fail (kernel arg charset)")
	}
	s = base()
	s.Volumes = []VolumeMount{{Name: "v", Path: "/w", HostPath: "/has:colon"}}
	if err := s.Validate(); err == nil {
		t.Fatal("host_path with colon must fail (kernel arg charset)")
	}
}
