// Package spec defines TaskSpec — the control contract that describes HOW a
// workload is executed (as opposed to the prompt, which describes the goal).
//
// This is the single source of truth consumed by umlctl/agentpvm (-config),
// the lifecycle FSM (internal/lifecycle), and every policy plane (identity,
// egress, tool gateway, artifact gate, approval). Everything that plan.md §9
// calls "policy already resolved" lives here as a validated, versioned struct
// before the UML kernel is ever started.
package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/BurntSushi/toml"
)

// SpecVersion is the TaskSpec schema major version. Bumped on breaking changes
// to the on-disk TOML shape; used for forward-compatibility rejection.
const SpecVersion = 1

// Defaults for optional budget/lifecycle fields when the TOML omits them.
const (
	DefaultCPUMax        = 0 // 0 = no cgroup limit
	DefaultWallTimeout   = 30 * time.Minute
	DefaultTokenBudget   = 0 // 0 = unlimited
	DefaultNetBudgetMB   = 0 // 0 = unlimited
	DefaultCostBudgetUSD = 0 // 0 = unlimited (US Dollars, micro-US cents at the ledger)
	DefaultTokenTTL      = 15 * time.Minute
	// DefaultLearnTTL caps DNS-learned whitelist entries (P1-B) when the spec
	// sets no learn_ttl.
	DefaultLearnTTL = 5 * time.Minute
	// DefaultMaxLearnedEntries bounds one task's DNS-learned IP set when the
	// spec sets no max_learned_entries.
	DefaultMaxLearnedEntries = 256
	// MaxLearnedEntriesLimit is the upper bound Validate accepts for
	// network.max_learned_entries (sane-range guard against map pressure).
	MaxLearnedEntriesLimit = 4096
)

// DefaultApprovalTimeout bounds how long an approval ticket may pend.
const DefaultApprovalTimeout = 5 * time.Minute

// DefaultLifecycleTTL is the overall task lifetime when TTL is omitted.
const DefaultLifecycleTTL = 1 * time.Hour

// DefaultMaxRetries is the FSM retry cap when omitted.
const DefaultMaxRetries = 2

// TaskSpec is the full control contract (plan.md §9.2).
//
// Only Identity, Network, Tools, Budget, Approval, Artifacts, Lifecycle are
// "control" fields. Runtime/Workspace/Kernel/Init describe the UML sandbox the
// control plane wraps. umlctl consumes a subset (Runtime/Workspace/Kernel/Init
// + Network tap); agentpvm consumes the whole thing.
type TaskSpec struct {
	Version int `toml:"version" json:"version"` // schema version; must equal SpecVersion

	// --- identity (plan.md §3) ---
	// Caller is the human/service that authorized this task. Required.
	// Tenant scopes the task for multi-tenant quota segregation (plan.md §12).
	Caller   string   `toml:"caller" json:"caller"`
	Tenant   string   `toml:"tenant" json:"tenant"`
	Identity Identity `toml:"identity" json:"identity"`

	// --- runtime / sandbox shape ---
	Runtime   RuntimeSpec   `toml:"runtime" json:"runtime"`
	Workspace WorkspaceSpec `toml:"workspace" json:"workspace"`
	Kernel    KernelSpec    `toml:"kernel" json:"kernel"`

	// --- control planes ---
	Network   NetworkSpec   `toml:"network" json:"network"`
	Tools     []ToolRule    `toml:"tools" json:"tools"`
	Budget    BudgetSpec    `toml:"budget" json:"budget"`
	Approval  ApprovalSpec  `toml:"approval" json:"approval"`
	Artifacts ArtifactsSpec `toml:"artifacts" json:"artifacts"`
	Lifecycle LifecycleSpec `toml:"lifecycle" json:"lifecycle"`

	// --- volumes (per-sandbox persistent mounts) ---
	Volumes []VolumeMount `toml:"volumes" json:"volumes"`

	// --- security & isolation policy ---
	Security SecuritySpec `toml:"security" json:"security"`
}

// Identity describes the short-lived credential scope granted to the sandbox
// (plan.md §3.2). The Credential Broker mints tokens bounded by Scope and TTL;
// long-lived secrets NEVER enter the guest.
type Identity struct {
	// Scope is a list of capability strings the minted token carries, e.g.
	// "repo:read", "db:write:payments". Empty = no capabilities.
	Scope []string `toml:"scope" json:"scope"`
	// TTL is how long the broker-issued token stays valid.
	TTL string `toml:"ttl" json:"ttl"`
}

// RuntimeSpec selects the UML sandbox shape.
type RuntimeSpec struct {
	// Name is the human-readable task name (also used as container id prefix
	// when none is given on the CLI).
	Name string `toml:"name" json:"name"`
	// CPU is the cgroup v2 cpu.max quota (in "millicpu"/1000; 1000 = 1 full
	// CPU). 0 = unlimited.
	CPU int `toml:"cpu" json:"cpu"`
	// Memory is the cgroup v2 memory.max, e.g. "512M", "2G".
	Memory string `toml:"memory" json:"memory"`
	// CPUModel pins the UML skas/tt mode; empty = kernel default.
	CPUModel string `toml:"cpu_model" json:"cpu_model"`
}

// WorkspaceSpec describes the filesystem layout.
type WorkspaceSpec struct {
	// BaseImage is the read-only backing image shared by many sandboxes.
	BaseImage string `toml:"base_image" json:"base_image"`
	// Overlay is the per-sandbox qcow2 CoW path. If empty, a path under the
	// container state dir is synthesized at start time.
	Overlay string `toml:"overlay" json:"overlay"`
	// Init is the ABSOLUTE in-guest init path (the kernel command line's
	// init=... must be absolute), e.g. "/init.sh", "/sbin/init".
	Init string `toml:"init" json:"init"`
	// ExtraEnv is injected into the guest via the init contract. Values here
	// are NOT secrets — secrets come from the Credential Broker at runtime.
	ExtraEnv map[string]string `toml:"extra_env" json:"extra_env"`

	// CompactOnExit rebuilds the per-task qcow2 overlay in place right after
	// the sandbox exits: only allocated clusters are rewritten, zero clusters
	// become ZERO-flag entries, and unused preallocated metadata is dropped.
	// This is the pure-Go equivalent of `qemu-img convert -O qcow2` (no
	// qemu binaries) and keeps snapshot exports / state dirs small. Only
	// meaningful on the vhost path (use_vhost_blk=true); the ubd path mounts
	// the base directly and has no overlay to compact. Non-fatal: a compact
	// failure is logged + audited but does not flip a clean task to Failed.
	CompactOnExit bool `toml:"compact_on_exit" json:"compact_on_exit"`

	// Ephemeral makes the sandbox's disk writes non-persistent: the root
	// filesystem is mounted read-only (kernel cmdline "ro" instead of "rw",
	// plus a read-only block backend on the vhost path) and NO per-task qcow2
	// overlay is created — nothing the guest could persist ever reaches the
	// host disk. Writable scratch space is the guest's responsibility: an
	// ephemeral-aware init mounts tmpfs on /tmp, /var/tmp, /run, /dev/shm
	// (see uml/init-ephemeral.sh for the reference implementation). Declared
	// persistent volumes are still attached and preserved — explicit volume
	// mounts are user intent and are NOT discarded. Mutually exclusive with
	// compact_on_exit (nothing to compact) and workspace.overlay (no overlay
	// is ever created).
	Ephemeral bool `toml:"ephemeral" json:"ephemeral"`
}

// KernelSpec selects the UML kernel binary and its launch mode.
type KernelSpec struct {
	// Path to the UML kernel binary.
	Path string `toml:"path" json:"path"`
	// Virtio is retained for TOML compatibility but no longer selects the
	// network transport. Historically it was a single switch that wired BOTH
	// the block device (virtio_uml / vhost-user-blk) AND the network device.
	// Those are independent concerns: the block backend is selected by
	// UseVhostBlk, and the network device is ALWAYS vec0 (the vector
	// transport — the only UML net transport left in Linux >= 6.16; legacy
	// eth0=tuntap was removed upstream). New code should use UseVhostBlk
	// directly; this field has no effect on networking.
	Virtio bool `toml:"virtio" json:"virtio"`
	// UseVhostBlk serves the block device over vhost-user-blk. The agent
	// path always creates a qcow2 CoW overlay per task (the backing image
	// may be raw or qcow2; sniffed by cow.CreateOverlay), so this MUST be
	// true for `agentpvm run`. The default backend is the pure-Go server
	// (internal/vhost/vu); PVM_VHOST_BACKEND=qemu falls back to
	// qemu-storage-daemon.
	UseVhostBlk bool `toml:"use_vhost_blk" json:"use_vhost_blk"`
}

// NetworkSpec is the per-task network policy (plan.md §4). The egress allowlist
// is enforced at two layers: an L7 HTTP CONNECT proxy (domain/method/size) and
// an eBPF TC filter as the IP-floor (SSRF block + allowlisted-IP pin).
type NetworkSpec struct {
	// Enabled turns on networking at all. When false, the sandbox gets no TAP
	// and no proxy — fully isolated.
	Enabled bool `toml:"enabled" json:"enabled"`
	// Bridge is the host bridge name to attach the TAP to.
	Bridge string `toml:"bridge" json:"bridge"`
	// GatewayIP is the bridge CIDR, e.g. "10.0.0.1/24".
	GatewayIP string `toml:"gateway_ip" json:"gateway_ip"`
	// GuestIP optionally pins the guest's IPv4 address inside the bridge
	// subnet. Empty = the host IPAM allocates one (starting at offset .100)
	// and hands it to the guest via the pvm_ip= kernel parameter. When both
	// guest_ip and gateway_ip are set, guest_ip must lie inside the gateway
	// subnet and differ from the gateway address.
	GuestIP string `toml:"guest_ip" json:"guest_ip"`
	// TAP is the host TAP device name. If empty, derived from the task name.
	TAP string `toml:"tap" json:"tap"`
	// EgressAllowDomains is the L7 allowlist applied by the proxy.
	EgressAllowDomains []string `toml:"egress_allow_domains" json:"egress_allow_domains"`
	// EgressBlockDomains is an explicit denylist (takes precedence over allow).
	EgressBlockDomains []string `toml:"egress_block_domains" json:"egress_block_domains"`
	// MaxRequestBodyBytes caps HTTP request bodies leaving the sandbox. 0 = no cap.
	MaxRequestBodyBytes int64 `toml:"max_request_body_bytes" json:"max_request_body_bytes"`
	// QoSRate is a tc tbf rate, e.g. "10mbit". Empty = no shaping.
	QoSRate string `toml:"qos_rate" json:"qos_rate"`
	// EgressRules is the extended L7 rule set.
	// When non-empty, rule decisions take precedence over the flat allow/block
	// domain allowlist; the deny list is always evaluated first at the gateway
	// and can never be overridden by a rule.
	EgressRules []EgressRule `toml:"egress_rules" json:"egress_rules"`

	// DNSLearnEnabled turns on DNS-learned domain egress (todo.md P1-B,
	// DNS-answer snooping): a per-task UDP DNS proxy
	// snoops resolver responses and inserts the resolved public IPs of
	// ALLOWLISTED domains into the task's eBPF whitelist map with a TTL, so
	// the IP-floor admits exactly the addresses the guest actually resolved.
	DNSLearnEnabled bool `toml:"dns_learn_enabled" json:"dns_learn_enabled"`
	// LearnTTL caps how long a learned IP stays whitelisted (Go duration,
	// default DefaultLearnTTL). The effective per-entry lifetime is
	// min(DNS TTL, learn_ttl) so a short-lived DNS answer never lingers.
	LearnTTL string `toml:"learn_ttl" json:"learn_ttl"`
	// DNSUpstream is the resolver the DNS proxy forwards to, "IP" or
	// "IP:port". Empty = the host's first /etc/resolv.conf nameserver.
	DNSUpstream string `toml:"dns_upstream" json:"dns_upstream"`
	// MaxLearnedEntries bounds the per-task learned IP set (default
	// DefaultMaxLearnedEntries) so a hostile guest cannot exhaust eBPF map
	// capacity or host memory by flooding distinct allowlisted lookups.
	MaxLearnedEntries int `toml:"max_learned_entries" json:"max_learned_entries"`

	// Dataplane selects the packet data plane:
	//   "bridge" (default) — TAP enslaved to a Linux bridge; the guest IP
	//     comes from the per-bridge IPAM (gateway_ip subnet) and the eBPF TC
	//     program on the TAP egress is the SSRF IP-floor.
	//   "tc" — opt-in bridgeless mode: NO bridge, no iptables. Every sandbox
	//     gets the SAME fixed link-local addressing (guest 169.254.68.6,
	//     gateway/proxy 169.254.68.5); TC-attached eBPF programs SNAT guest
	//     traffic out the host NIC and reverse-NAT replies via a per-task
	//     session table. bridge/gateway_ip/guest_ip are IGNORED in tc mode
	//     (pvm_ip=169.254.68.6 and egress_proxy=169.254.68.5:<port> are
	//     injected instead). IPv4 TCP/UDP only; ICMP is dropped.
	//   "auto" — prefer the tc plane when the environment can load it
	//     (root/CAP_NET_ADMIN + compiled BPF objects) and no port mappings
	//     are requested; fall back to bridge otherwise. The choice is
	//     audit-recorded either way.
	Dataplane string `toml:"dataplane" json:"dataplane"`

	// PortMappings publishes host ports that forward inbound connections
	// to the task's guest (bridge dataplane only; in tc mode the launch
	// degrades with an audited warning — the bridgeless plane reverse-NATs
	// established sessions only).
	//
	//	[[network.port_mappings]]
	//	host_port  = 8080
	//	guest_port = 80
	//	protocol   = "tcp"   # or "udp"; default tcp
	PortMappings []PortMappingSpec `toml:"port_mappings" json:"port_mappings"`
}

// PortMappingSpec is one inbound host-port forward declared by a task.
type PortMappingSpec struct {
	HostPort  int    `toml:"host_port" json:"host_port"`
	GuestPort int    `toml:"guest_port" json:"guest_port"`
	Protocol  string `toml:"protocol" json:"protocol"`
}

// Dataplane mode values for NetworkSpec.Dataplane.
const (
	// DataplaneBridge is the default: Linux bridge + per-bridge IPAM.
	DataplaneBridge = "bridge"
	// DataplaneTC is the opt-in bridgeless TC/eBPF data plane.
	DataplaneTC = "tc"
	// DataplaneAuto prefers the tc plane when the environment supports it
	// and no port mappings are declared; falls back to bridge otherwise.
	DataplaneAuto = "auto"
)

// EgressRule is one L7 egress rule (Match fields AND-combined).
type EgressRule struct {
	Name   string        `toml:"name" json:"name"`
	Host   string        `toml:"host" json:"host"`     // exact or "*.suffix"
	SNI    string        `toml:"sni" json:"sni"`       // TLS SNI, same wildcard as Host
	Method []string      `toml:"method" json:"method"` // OR within list
	Path   string        `toml:"path" json:"path"`     // exact or "/prefix/*"
	Scheme string        `toml:"scheme" json:"scheme"` // "http" | "https"
	Port   int           `toml:"port" json:"port"`     // 1..65535, 0 = default 80/443
	Allow  *bool         `toml:"allow" json:"allow"`   // nil = allow=true
	Inject *EgressInject `toml:"inject" json:"inject"`
	// MITM opts the rule into TLS interception so Inject can run on HTTPS
	// traffic (egress CA terminates the guest's TLS; the guest rootfs must
	// trust the CA). Injection applies to HTTPS rules.
	MITM *bool `toml:"mitm" json:"mitm"`
}

// EgressInject carries credential injection for one rule.
type EgressInject struct {
	Header string `toml:"header" json:"header"`
	Format string `toml:"format" json:"format"` // e.g. "Bearer ${SECRET}", default "${SECRET}"
	Secret string `toml:"secret" json:"secret"`
	// AllowPlainHTTP attaches the secret even on plaintext HTTP upstreams
	// (the boundary is that the sandbox never
	// sees it). Default false: HTTPS only.
	AllowPlainHTTP bool `toml:"allow_plain_http" json:"allow_plain_http"`
}

// ToolRule is one row of the tool gateway decision matrix (plan.md §6.2).
// Every tool call from the agent is matched against these rules in order; the
// first match wins. A default-deny catch-all is auto-appended.
type ToolRule struct {
	// Name matches the tool name (exact, or "*" for wildcard).
	Name string `toml:"name" json:"name"`
	// Action is one of: allow, constrain, approve, deny.
	Action string `toml:"action" json:"action"`
	// Effect records what the rule governs — informational, used in audit.
	Effect string `toml:"effect" json:"effect"`
	// Reason is surfaced to the agent on deny/approve.
	Reason string `toml:"reason" json:"reason"`
}

// BudgetSpec is the hard resource/cost ceiling (plan.md §9.2 Budget).
type BudgetSpec struct {
	// MaxWallTime is the absolute wall-clock cap; on expiry the lifecycle FSM
	// moves the task to Destroy with reason "timeout".
	MaxWallTime string `toml:"max_wall_time" json:"max_wall_time"`
	// MaxTokens caps total LLM tokens consumed by the agent loop. 0 = unlimited.
	MaxTokens int `toml:"max_tokens" json:"max_tokens"`
	// MaxNetworkMB caps total egress bytes (MB). 0 = unlimited.
	MaxNetworkMB int `toml:"max_network_mb" json:"max_network_mb"`
	// MaxCostMicroUSD caps total spend in micro-USD. 0 = unlimited.
	MaxCostMicroUSD int `toml:"max_cost_micro_usd" json:"max_cost_micro_usd"`
}

// ApprovalSpec defines the effect boundary — which tool actions require a human
// approval ticket before they may proceed (plan.md §10).
type ApprovalSpec struct {
	// RequiredFor lists tool actions that must pause for approval:
	// any of "send","delete","write-prod","pay","deploy","prod".
	RequiredFor []string `toml:"required_for" json:"required_for"`
	// Notify is where approval requests are sent (currently logged + queued;
	// reserved for webhooks/IM).
	Notify string `toml:"notify" json:"notify"`
	// Timeout is how long an approval may pend before auto-deny.
	Timeout string `toml:"timeout" json:"timeout"`
}

// ArtifactsSpec declares the sandbox's outputs (plan.md §5.3, §7).
// Only declared outputs may leave the sandbox; everything else stays inside.
type ArtifactsSpec struct {
	// Declared is the list of guest paths treated as outputs (diff/build/report).
	Declared []string `toml:"declared" json:"declared"`
	// RequireTestsPassed gates release on a green verifier run.
	RequireTestsPassed bool `toml:"require_tests_passed" json:"require_tests_passed"`
	// BlockSecrets blocks release if a declared artifact diff contains secrets.
	BlockSecrets bool `toml:"block_secrets" json:"block_secrets"`
}

// VolumeMount declares one persistent volume attachment. Mirrors
// sdk/go:VolumeMount{Name, Path, ReadOnly} and the TOML form:
//
//	[[volumes]]
//	name = "my-data"
//	path = "/workspace"
//	driver = "builtin"    # optional, defaults to first registered plugin
//	read_only = true
//	host_path = "/srv/shared/dataset"  # optional EXPLICIT host-directory
//	                                 # mount: gated on the deployment-wide
//	                                 # PVM_HOST_MOUNT_PREFIXES whitelist;
//	                                 # the dir must already exist. Mutually
//	                                 # meaningful only with the builtin driver.
type VolumeMount struct {
	Name     string `toml:"name" json:"name"`
	Path     string `toml:"path" json:"path"`
	Driver   string `toml:"driver" json:"driver"`
	ReadOnly bool   `toml:"read_only" json:"read_only"`
	// HostPath requests an explicit host-directory mount (builtin driver
	// only). Enforced against PVM_HOST_MOUNT_PREFIXES at attach time —
	// see internal/volume/hostmount.go.
	HostPath string `toml:"host_path" json:"host_path,omitempty"`
}

// SecuritySpec defines host security and isolation policies for the sandbox.
type SecuritySpec struct {
	// AllowInsecureDegraded allows task launch to proceed even if host security
	// primitives (Landlock LSM, User Namespace, Seccomp) are not supported by
	// the host kernel or environment. Defaults to false (fail-closed).
	//
	// Since the rootless jail (TODO.md "[P1] Jail rootless 化"), a privileged
	// launch without usable user namespaces additionally reports the
	// "user-namespace" layer: the monitor then runs with the legacy
	// mountns-only jail — seccomp/capability CONSTRAINTS on a real-root
	// supervisor, not the NEWUSER+NEWPID hard boundary (zero init_user_ns
	// capabilities, host processes unaddressable). Degraded mode also skips
	// the host-side tap fd handoff (vec0 falls back to transport=tap, which
	// needs the monitor to hold CAP_NET_ADMIN), so it is strictly a
	// compatibility escape hatch, never the target posture. Every degraded
	// launch is audit-recorded (security:degraded_warning).
	AllowInsecureDegraded bool `toml:"allow_insecure_degraded" json:"allow_insecure_degraded"`
	// EnforceHostSeccomp enables host-level seccomp-bpf filtering for the UML process.
	// Defaults to true when the key is absent from the TOML: LoadFile/LoadString
	// materialize the default via toml.MetaData (a plain bool cannot tell "unset"
	// apart from an explicit false). An explicit `enforce_host_seccomp = false`
	// is honored. TaskSpecs built programmatically (no TOML decode) must set it.
	EnforceHostSeccomp bool `toml:"enforce_host_seccomp" json:"enforce_host_seccomp"`
	// EnforceLandlock enables Landlock LSM path lockdown for hostfs volumes.
	// Same defaulting rule as EnforceHostSeccomp: true unless explicitly set.
	EnforceLandlock bool `toml:"enforce_landlock" json:"enforce_landlock"`
	// UMLSeccomp selects the UML kernel's fast seccomp userspace mode via the
	// runtime kernel command-line parameter `seccomp=on|auto|off` (mainline
	// x86_64 since Linux 6.16; the aarch64 zalexdev port enables the same
	// mechanism in defconfig). "on" is fail-closed at kernel boot,
	// "auto" falls back to ptrace silently, "off" (default) keeps ptrace.
	//
	// SECURITY TRADE-OFF (upstream help text): with seccomp mode the guest
	// userspace can read/write guest physical memory and can interfere with
	// the stub's SIGALRM — guest kernel integrity is no longer guaranteed,
	// so in-guest cgroup enforcement (MEMCG/pids, tests/09) becomes advisory.
	// The host-side jail boundary is unaffected. This is therefore opt-in per
	// task, and every on/auto launch is audit-recorded (security:uml_seccomp).
	UMLSeccomp string `toml:"uml_seccomp" json:"uml_seccomp"`
}

// ValidateMountPath rejects guest mount points that would corrupt the
// hostfs_volume kernel argument. The path is embedded verbatim as
// hostfs_volume=<host>:<guest>:<mode>, so whitespace splits the kernel
// command line while ":" and "," are field/list separators — any of them
// turns one mount into a garbage parameter. TaskSpec.Validate enforces this
// rule, and container.StartTask re-checks it before attaching (a public
// entry point must not assume its caller validated).
// Character-set contracts for fields interpolated into the UML kernel
// command line / host-side tooling argv. Kept side by side with the mount-path
// rules so all kernel-adjacent validation lives in one place.
var (
	initPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	tapNameRe  = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)
)

// validateImagePath guards a host-side image path (BaseImage/Overlay): it is
// opened by the cow engine and interpolated into ubd0=…, so it must not
// contain whitespace/':'/',' (kernel-arg and vec0 sub-parameter separators,
// remote-source prefixes like json:/nbd:) and must not start with '-' — but
// it MAY be relative: the shipped default TaskSpec uses base_image =
// "rootfs.img" relative to the launch directory.
func validateImagePath(field, val string) error {
	if strings.ContainsAny(val, " \t\n\r,:") {
		return fmt.Errorf("spec: %s must not contain whitespace, comma, or colon", field)
	}
	first := val
	if idx := strings.IndexByte(val, '/'); idx >= 0 {
		first = val[:idx]
	}
	if strings.HasPrefix(first, "-") {
		return fmt.Errorf("spec: %s must not start with '-'", field)
	}
	return nil
}

func ValidateMountPath(path string) error {
	if path == "" {
		return fmt.Errorf("volume path is required")
	}
	for _, r := range path {
		switch {
		case unicode.IsSpace(r):
			return fmt.Errorf("volume path %q contains whitespace (breaks hostfs_volume=<host>:<guest>:<mode>)", path)
		case r == ':' || r == ',':
			return fmt.Errorf("volume path %q contains separator %q (breaks hostfs_volume=<host>:<guest>:<mode>)", path, r)
		}
	}
	return nil
}

// LifecycleSpec is the task lifecycle policy (plan.md §8, §11).
type LifecycleSpec struct {
	// Paused starts the task in Suspended state (checkpoint-on-start).
	Paused bool `toml:"paused" json:"paused"`
	// MaxRetries is how many times the FSM may auto-retry Failed -> Provisioning.
	MaxRetries int `toml:"max_retries" json:"max_retries"`
	// OnAnomaly is the incident posture: "pause" (default) or "terminate".
	OnAnomaly string `toml:"on_anomaly" json:"on_anomaly"`
	// TTL is the task's overall lifetime; on expiry the task is Destroyed.
	TTL string `toml:"ttl" json:"ttl"`
	// IdleTimeout triggers AutoPause: after this much idle time the task is
	// frozen (cgroup freeze) and moved to Suspended. Empty = disabled.
	// timeout + on_timeout=pause semantics.
	IdleTimeout string `toml:"idle_timeout" json:"idle_timeout"`
	// DeepPause upgrades the idle pause from a cgroup freeze (CPU only) to
	// a CRIU checkpoint + kill: host memory drops to zero, resume revives
	// the exact execution state. Requires criu on the host; failures fall
	// back to the shallow freeze with a warning.
	DeepPause bool `toml:"deep_pause" json:"deep_pause"`
	// AutoResume re-arms a Suspended task on the next API activity (any
	// /exec, /tasks/:id/*).
	AutoResume bool `toml:"auto_resume" json:"auto_resume"`
}

// --- loading & validation ---

// validateDNSUpstream checks network.dns_upstream is a bare IPv4/IPv6
// address (port 53 implied) or IP:port with a numeric port in 1..65535.
// Hostnames are deliberately rejected: the DNS-learn proxy must not itself
// depend on untrusted DNS to find its resolver.
func validateDNSUpstream(up string) error {
	if ip := net.ParseIP(up); ip != nil {
		return nil
	}
	host, port, err := net.SplitHostPort(up)
	if err != nil {
		return fmt.Errorf("spec: network.dns_upstream %q must be IP or IP:port: %v", up, err)
	}
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("spec: network.dns_upstream %q: host %q is not an IP", up, host)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("spec: network.dns_upstream %q: invalid port %q", up, port)
	}
	return nil
}

// LoadFile reads, parses and validates a TaskSpec from a TOML file.
func LoadFile(path string) (*TaskSpec, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("spec: config file not found: %s: %w", path, err)
	}
	var s TaskSpec
	md, err := toml.DecodeFile(path, &s)
	if err != nil {
		return nil, fmt.Errorf("spec: parse %s: %w", path, err)
	}
	applySecurityDefaults(&s, md)
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		// Unknown keys are a config-error signal (typo, stale field). Surface them.
		return nil, fmt.Errorf("spec: unknown keys in %s: %v", path, undecoded)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// applySecurityDefaults materializes the documented "default true" for the
// host-enforcement toggles ONLY when the key was absent from the TOML — a
// plain bool zero value cannot distinguish "unset" from "explicit false"
// after decode, so without this a config that simply omits the [security]
// keys would silently launch WITHOUT seccomp/Landlock enforcement.
// container.StartTask consumes these fields verbatim (jail.CheckSecurity and
// SetupJail), so they must be correct coming out of the loader.
func applySecurityDefaults(s *TaskSpec, md toml.MetaData) {
	if !md.IsDefined("security", "enforce_host_seccomp") {
		s.Security.EnforceHostSeccomp = true
	}
	if !md.IsDefined("security", "enforce_landlock") {
		s.Security.EnforceLandlock = true
	}
}

// LoadString parses and validates a TaskSpec from an in-memory TOML string.
// Used by the /api/tasks/load-spec endpoint when the UI submits content directly.
func LoadString(content string) (*TaskSpec, error) {
	var s TaskSpec
	md, err := toml.Decode(content, &s)
	if err != nil {
		return nil, fmt.Errorf("spec: parse: %w", err)
	}
	applySecurityDefaults(&s, md)
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("spec: unknown keys: %v", undecoded)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks the TaskSpec is internally consistent and fills defaults.
// It does NOT check runtime availability (kernel exists, etc.) — that's the
// launcher's job.
func (s *TaskSpec) Validate() error {
	var errs []error
	if s.Version == 0 {
		s.Version = SpecVersion // accept missing version as current
	}
	if s.Version != SpecVersion {
		return fmt.Errorf("spec: version mismatch: file has %d, supported is %d", s.Version, SpecVersion)
	}
	if s.Caller == "" {
		errs = append(errs, errors.New("spec: caller is required (who authorized this task)"))
	}
	if s.Runtime.CPU < 0 {
		errs = append(errs, fmt.Errorf("spec: runtime.cpu must be >= 0"))
	}
	if s.Runtime.CPU > 1024 {
		errs = append(errs, fmt.Errorf("spec: runtime.cpu must be <= 1024"))
	}
	if s.Runtime.Memory != "" {
		memBytes, err := parseMem(s.Runtime.Memory)
		if err != nil {
			errs = append(errs, fmt.Errorf("spec: runtime.memory: %w", err))
		} else if memBytes < 0 {
			errs = append(errs, fmt.Errorf("spec: runtime.memory must be >= 0"))
		}
	}
	// Kernel-command-line interpolation safety: Init, TAP, BaseImage and
	// Overlay land verbatim in the UML argv (init=%s, vec0:...,ifname=%s,
	// ubd0=%s), and the kernel re-splits argv on whitespace with ',' splitting
	// vec sub-parameters — so anything outside these inert sets is an
	// injection primitive (see the container package's validateKernelField,
	// which re-checks at build time as defense in depth).
	if s.Workspace.Init != "" && !initPathRe.MatchString(s.Workspace.Init) {
		errs = append(errs, fmt.Errorf("spec: workspace.init %q must match ^/[A-Za-z0-9._/-]+$", s.Workspace.Init))
	}
	if s.Network.TAP != "" && !tapNameRe.MatchString(s.Network.TAP) {
		errs = append(errs, fmt.Errorf("spec: network.tap %q must match ^[a-zA-Z0-9_-]{1,15}$", s.Network.TAP))
	}
	// Data plane selection (P2). Empty fills the historical default; an
	// unrecognized value is a config error, never silently ignored — the
	// enforcement posture differs too much between modes to guess.
	switch s.Network.Dataplane {
	case "":
		s.Network.Dataplane = DataplaneBridge
	case DataplaneBridge, DataplaneTC, DataplaneAuto:
	default:
		errs = append(errs, fmt.Errorf("spec: network.dataplane %q must be %q, %q or %q",
			s.Network.Dataplane, DataplaneBridge, DataplaneTC, DataplaneAuto))
	}
	for i, pm := range s.Network.PortMappings {
		if pm.HostPort < 1 || pm.HostPort > 65535 {
			errs = append(errs, fmt.Errorf("spec: network.port_mappings[%d].host_port %d out of range", i, pm.HostPort))
		}
		if pm.GuestPort < 1 || pm.GuestPort > 65535 {
			errs = append(errs, fmt.Errorf("spec: network.port_mappings[%d].guest_port %d out of range", i, pm.GuestPort))
		}
		switch pm.Protocol {
		case "", "tcp", "udp":
		default:
			errs = append(errs, fmt.Errorf("spec: network.port_mappings[%d].protocol %q must be tcp or udp", i, pm.Protocol))
		}
	}
	seenHost := map[string]bool{}
	for i, pm := range s.Network.PortMappings {
		proto := pm.Protocol
		if proto == "" {
			proto = "tcp"
		}
		k := fmt.Sprintf("%s/%d", proto, pm.HostPort)
		if seenHost[k] {
			errs = append(errs, fmt.Errorf("spec: network.port_mappings[%d] duplicates host port %s", i, k))
		}
		seenHost[k] = true
	}
	// guest_ip lands verbatim in the kernel command line as pvm_ip=<ip>, so
	// it must be a plain dotted-quad IPv4 (which the kernel-field charset
	// check then re-verifies). When the gateway CIDR is also set, the guest
	// address must live inside that subnet — an out-of-subnet guest IP would
	// be unreachable and is a config error, not a runtime surprise.
	// Skipped in tc mode: the data plane pins 169.254.68.6/169.254.68.5 and
	// IGNORES guest_ip/gateway_ip, so cross-checking them would reject
	// configs that are valid under the tc contract.
	if s.Network.GuestIP != "" && s.Network.Dataplane != DataplaneTC {
		ip := net.ParseIP(s.Network.GuestIP)
		if ip == nil || ip.To4() == nil {
			errs = append(errs, fmt.Errorf("spec: network.guest_ip %q is not a valid IPv4 address", s.Network.GuestIP))
		} else if s.Network.GatewayIP != "" {
			gwIP, ipnet, err := net.ParseCIDR(s.Network.GatewayIP)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("spec: network.gateway_ip %q is not a valid CIDR: %v", s.Network.GatewayIP, err))
			case !ipnet.Contains(ip):
				errs = append(errs, fmt.Errorf("spec: network.guest_ip %q is outside the bridge subnet %s", s.Network.GuestIP, s.Network.GatewayIP))
			case gwIP.Equal(ip):
				errs = append(errs, fmt.Errorf("spec: network.guest_ip %q collides with the gateway address", s.Network.GuestIP))
			}
		}
	}
	// DNS-learned egress (P1-B) knobs. Validated regardless of
	// dns_learn_enabled: a malformed value is a config error signal, not
	// something to defer until the feature is switched on.
	if s.Network.LearnTTL != "" {
		d, err := time.ParseDuration(s.Network.LearnTTL)
		if err != nil {
			errs = append(errs, fmt.Errorf("spec: network.learn_ttl: %w", err))
		} else if d <= 0 {
			errs = append(errs, fmt.Errorf("spec: network.learn_ttl %q must be > 0", s.Network.LearnTTL))
		}
	} else {
		s.Network.LearnTTL = DefaultLearnTTL.String()
	}
	if s.Network.DNSUpstream != "" {
		if err := validateDNSUpstream(s.Network.DNSUpstream); err != nil {
			errs = append(errs, err)
		}
	}
	if s.Network.MaxLearnedEntries == 0 {
		s.Network.MaxLearnedEntries = DefaultMaxLearnedEntries
	} else if s.Network.MaxLearnedEntries < 0 || s.Network.MaxLearnedEntries > MaxLearnedEntriesLimit {
		errs = append(errs, fmt.Errorf("spec: network.max_learned_entries %d out of range (1..%d)",
			s.Network.MaxLearnedEntries, MaxLearnedEntriesLimit))
	}
	for _, f := range []struct{ field, val string }{
		{"workspace.base_image", s.Workspace.BaseImage},
		{"workspace.overlay", s.Workspace.Overlay},
	} {
		if f.val == "" {
			continue
		}
		if err := validateImagePath(f.field, f.val); err != nil {
			errs = append(errs, err)
		}
	}
	// Ephemeral consistency: an ephemeral sandbox never creates a qcow2
	// overlay, so the overlay lifecycle knobs are meaningless. Rejecting
	// them beats silently ignoring — a spec that asks to compact (or place)
	// an overlay that will never exist is almost certainly a config error.
	if s.Workspace.Ephemeral {
		if s.Workspace.CompactOnExit {
			errs = append(errs, errors.New("spec: workspace.compact_on_exit conflicts with "+
				"workspace.ephemeral (ephemeral tasks create no overlay to compact)"))
		}
		if s.Workspace.Overlay != "" {
			errs = append(errs, errors.New("spec: workspace.overlay conflicts with "+
				"workspace.ephemeral (ephemeral tasks never create an overlay)"))
		}
	}
	if s.Identity.TTL != "" {
		if _, err := time.ParseDuration(s.Identity.TTL); err != nil {
			errs = append(errs, fmt.Errorf("spec: identity.ttl: %w", err))
		}
	} else {
		s.Identity.TTL = DefaultTokenTTL.String()
	}
	for i := range s.Tools {
		switch s.Tools[i].Action {
		case "", "allow", "constrain", "approve", "deny":
		default:
			errs = append(errs, fmt.Errorf("spec: tools[%d].action %q invalid (allow|constrain|approve|deny)", i, s.Tools[i].Action))
		}
	}
	if s.Budget.MaxWallTime != "" {
		if _, err := time.ParseDuration(s.Budget.MaxWallTime); err != nil {
			errs = append(errs, fmt.Errorf("spec: budget.max_wall_time: %w", err))
		}
	} else {
		s.Budget.MaxWallTime = DefaultWallTimeout.String()
	}
	if s.Lifecycle.TTL != "" {
		if _, err := time.ParseDuration(s.Lifecycle.TTL); err != nil {
			errs = append(errs, fmt.Errorf("spec: lifecycle.ttl: %w", err))
		}
	} else {
		s.Lifecycle.TTL = DefaultLifecycleTTL.String()
	}
	if s.Lifecycle.MaxRetries == 0 {
		s.Lifecycle.MaxRetries = DefaultMaxRetries
	}
	if s.Lifecycle.OnAnomaly == "" {
		s.Lifecycle.OnAnomaly = "pause"
	}
	if s.Security.UMLSeccomp == "" {
		s.Security.UMLSeccomp = "off"
	}
	switch s.Security.UMLSeccomp {
	case "on", "auto", "off":
	default:
		errs = append(errs, fmt.Errorf("spec: security.uml_seccomp %q invalid (on|auto|off)", s.Security.UMLSeccomp))
	}
	switch s.Lifecycle.OnAnomaly {
	case "pause", "terminate":
	default:
		errs = append(errs, fmt.Errorf("spec: lifecycle.on_anomaly %q invalid (pause|terminate)", s.Lifecycle.OnAnomaly))
	}
	if s.Approval.Timeout != "" {
		if _, err := time.ParseDuration(s.Approval.Timeout); err != nil {
			errs = append(errs, fmt.Errorf("spec: approval.timeout: %w", err))
		}
	} else {
		s.Approval.Timeout = DefaultApprovalTimeout.String()
	}
	// the artifact gate's block-secrets flag is meaningful only if there are
	// declared outputs; warn (not fail) so an empty declared list is allowed.
	if s.Artifacts.BlockSecrets && len(s.Artifacts.Declared) == 0 {
		// not fatal — a task may declare no outputs.
	}
	seenPaths := make(map[string]bool)
	for i, vm := range s.Volumes {
		if vm.Name == "" {
			errs = append(errs, fmt.Errorf("spec: volumes[%d].name is required", i))
		}
		if vm.Path == "" {
			errs = append(errs, fmt.Errorf("spec: volumes[%d].path is required", i))
			continue
		}
		// The guest mount point is embedded verbatim in the kernel cmdline as
		// hostfs_volume=<host>:<guest>:<mode>; whitespace/":"/"," would
		// corrupt that parameter (see ValidateMountPath).
		if err := ValidateMountPath(vm.Path); err != nil {
			errs = append(errs, fmt.Errorf("spec: volumes[%d].path: %w", i, err))
		}
		// An explicit host_path shares the kernel-arg charset rules (it is
		// spliced into hostfs_volume=<host>:<guest>:<mode>) and must be
		// absolute. The PREFIX whitelist is enforced at attach time by the
		// volume Manager (deployment env), not here — a spec is valid
		// against a deployment that allows its prefixes.
		if vm.HostPath != "" {
			if !filepath.IsAbs(filepath.Clean(vm.HostPath)) {
				errs = append(errs, fmt.Errorf("spec: volumes[%d].host_path %q must be absolute", i, vm.HostPath))
			} else if err := ValidateMountPath(vm.HostPath); err != nil {
				errs = append(errs, fmt.Errorf("spec: volumes[%d].host_path: %w", i, err))
			}
		}
		// Normalize before validation so equivalent spellings of the same
		// mount point (trailing slashes, interior "..") are caught as
		// duplicates and share one absolute-path check. The error messages
		// keep the original spelling.
		clean := filepath.Clean(vm.Path)
		if !filepath.IsAbs(clean) {
			errs = append(errs, fmt.Errorf("spec: volumes[%d].path %q must be absolute", i, vm.Path))
		} else if seenPaths[clean] {
			errs = append(errs, fmt.Errorf("spec: volumes[%d].path %q duplicates an earlier mount", i, vm.Path))
		} else {
			seenPaths[clean] = true
		}
	}
	if s.Lifecycle.IdleTimeout != "" {
		d, err := time.ParseDuration(s.Lifecycle.IdleTimeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("spec: lifecycle.idle_timeout: %w", err))
		} else if d <= 0 {
			errs = append(errs, fmt.Errorf("spec: lifecycle.idle_timeout must be positive, got %q", s.Lifecycle.IdleTimeout))
		}
	}
	return errors.Join(errs...)
}

// Fingerprint returns a stable hex SHA-256 of the validated spec. This is the
// "SPEC + VERSION" evidence record (plan.md §14.2 phase 02): two tasks with
// the same fingerprint ran under identical control contracts.
//
// The hash is computed over a normalized JSON serialization of the full
// TaskSpec so that ANY control-plane field contributes to the fingerprint.
// Adding a new field therefore cannot silently slip out of the evidence record.
// JSON map keys are sorted by encoding/json, and array order is preserved as
// declared (tools / allow_domains are treated as significant — reordering them
// changes the contract).
func (s *TaskSpec) Fingerprint() string {
	// Clear runtime-only / non-contract fields before hashing. Caller, Tenant,
	// Version and every control plane stays in — they ARE the contract.
	snapshot := *s // shallow copy; we only nil out non-contract extras here
	// (No fields are currently excluded; the whole struct is the contract.)
	enc, err := json.Marshal(snapshot)
	if err != nil {
		// Marshal of a struct without channels/funcs cannot fail; fall back to
		// a stable textual form so Fingerprint never returns empty.
		h := sha256.New()
		fmt.Fprintf(h, "%+v", snapshot)
		return hex.EncodeToString(h.Sum(nil))
	}
	h := sha256.New()
	h.Write(enc)
	return hex.EncodeToString(h.Sum(nil))
}

// parseMem is a local byte-parser to avoid an import cycle with internal/config
// (which has ParseMemory). Accepts 512M/2G/etc. Returns an error on negative
// values or unsupported units.
func parseMem(s string) (int64, error) {
	var v int64
	var unit string
	n, err := fmt.Sscanf(s, "%d%s", &v, &unit)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid memory %q", s)
	}
	if v < 0 {
		return 0, fmt.Errorf("negative memory %q", s)
	}
	switch unit {
	case "K", "k", "KB", "kb":
		return v * 1024, nil
	case "M", "m", "MB", "mb":
		return v * 1024 * 1024, nil
	case "G", "g", "GB", "gb":
		return v * 1024 * 1024 * 1024, nil
	case "":
		return v, nil
	}
	return 0, fmt.Errorf("unsupported memory unit %q", unit)
}
