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
	"os"
	"time"

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
	Version int `toml:"version"` // schema version; must equal SpecVersion

	// --- identity (plan.md §3) ---
	// Caller is the human/service that authorized this task. Required.
	// Tenant scopes the task for multi-tenant quota segregation (plan.md §12).
	Caller   string   `toml:"caller"`
	Tenant   string   `toml:"tenant"`
	Identity Identity `toml:"identity"`

	// --- runtime / sandbox shape ---
	Runtime   RuntimeSpec   `toml:"runtime"`
	Workspace WorkspaceSpec `toml:"workspace"`
	Kernel    KernelSpec    `toml:"kernel"`

	// --- control planes ---
	Network   NetworkSpec   `toml:"network"`
	Tools     []ToolRule    `toml:"tools"`
	Budget    BudgetSpec    `toml:"budget"`
	Approval  ApprovalSpec  `toml:"approval"`
	Artifacts ArtifactsSpec `toml:"artifacts"`
	Lifecycle LifecycleSpec `toml:"lifecycle"`

	// --- volumes (Cube parity: per-sandbox persistent mounts) ---
	Volumes []VolumeMount `toml:"volumes"`
}

// Identity describes the short-lived credential scope granted to the sandbox
// (plan.md §3.2). The Credential Broker mints tokens bounded by Scope and TTL;
// long-lived secrets NEVER enter the guest.
type Identity struct {
	// Scope is a list of capability strings the minted token carries, e.g.
	// "repo:read", "db:write:payments". Empty = no capabilities.
	Scope []string `toml:"scope"`
	// TTL is how long the broker-issued token stays valid.
	TTL string `toml:"ttl"`
}

// RuntimeSpec selects the UML sandbox shape.
type RuntimeSpec struct {
	// Name is the human-readable task name (also used as container id prefix
	// when none is given on the CLI).
	Name string `toml:"name"`
	// CPU is the cgroup v2 cpu.max quota (in "millicpu"/1000; 1000 = 1 full
	// CPU). 0 = unlimited.
	CPU int `toml:"cpu"`
	// Memory is the cgroup v2 memory.max, e.g. "512M", "2G".
	Memory string `toml:"memory"`
	// CPUModel pins the UML skas/tt mode; empty = kernel default.
	CPUModel string `toml:"cpu_model"`
}

// WorkspaceSpec describes the filesystem layout.
type WorkspaceSpec struct {
	// BaseImage is the read-only backing image shared by many sandboxes.
	BaseImage string `toml:"base_image"`
	// Overlay is the per-sandbox qcow2 CoW path. If empty, a path under the
	// container state dir is synthesized at start time.
	Overlay string `toml:"overlay"`
	// Init is the in-guest init command, e.g. "/init.sh", "/sbin/init".
	Init string `toml:"init"`
	// ExtraEnv is injected into the guest via the init contract. Values here
	// are NOT secrets — secrets come from the Credential Broker at runtime.
	ExtraEnv map[string]string `toml:"extra_env"`

	// CompactOnExit rebuilds the per-task qcow2 overlay in place right after
	// the sandbox exits: only allocated clusters are rewritten, zero clusters
	// become ZERO-flag entries, and unused preallocated metadata is dropped.
	// This is the pure-Go equivalent of `qemu-img convert -O qcow2` (no
	// qemu binaries) and keeps snapshot exports / state dirs small. Only
	// meaningful on the vhost path (use_vhost_blk=true); the ubd path mounts
	// the base directly and has no overlay to compact. Non-fatal: a compact
	// failure is logged + audited but does not flip a clean task to Failed.
	CompactOnExit bool `toml:"compact_on_exit"`
}

// KernelSpec selects the UML kernel binary and its launch mode.
type KernelSpec struct {
	// Path to the UML kernel binary.
	Path string `toml:"path"`
	// Virtio is retained for TOML compatibility but no longer selects the
	// network transport. Historically it was a single switch that wired BOTH
	// the block device (virtio_uml / vhost-user-blk) AND the network device.
	// Those are independent concerns: the block backend is selected by
	// UseVhostBlk, and the network device is ALWAYS vec0 (the vector
	// transport — the only UML net transport left in Linux >= 6.16; legacy
	// eth0=tuntap was removed upstream). New code should use UseVhostBlk
	// directly; this field has no effect on networking.
	Virtio bool `toml:"virtio"`
	// UseVhostBlk serves the block device over vhost-user-blk. The agent
	// path always creates a qcow2 CoW overlay per task (the backing image
	// may be raw or qcow2; sniffed by cow.CreateOverlay), so this MUST be
	// true for `agentpvm run`. The default backend is the pure-Go server
	// (internal/vhost/vu); PVM_VHOST_BACKEND=qemu falls back to
	// qemu-storage-daemon.
	UseVhostBlk bool `toml:"use_vhost_blk"`
}

// NetworkSpec is the per-task network policy (plan.md §4). The egress allowlist
// is enforced at two layers: an L7 HTTP CONNECT proxy (domain/method/size) and
// an eBPF TC filter as the IP-floor (SSRF block + allowlisted-IP pin).
type NetworkSpec struct {
	// Enabled turns on networking at all. When false, the sandbox gets no TAP
	// and no proxy — fully isolated.
	Enabled bool `toml:"enabled"`
	// Bridge is the host bridge name to attach the TAP to.
	Bridge string `toml:"bridge"`
	// GatewayIP is the bridge CIDR, e.g. "10.0.0.1/24".
	GatewayIP string `toml:"gateway_ip"`
	// TAP is the host TAP device name. If empty, derived from the task name.
	TAP string `toml:"tap"`
	// EgressAllowDomains is the L7 allowlist applied by the proxy.
	EgressAllowDomains []string `toml:"egress_allow_domains"`
	// EgressBlockDomains is an explicit denylist (takes precedence over allow).
	EgressBlockDomains []string `toml:"egress_block_domains"`
	// MaxRequestBodyBytes caps HTTP request bodies leaving the sandbox. 0 = no cap.
	MaxRequestBodyBytes int64 `toml:"max_request_body_bytes"`
	// QoSRate is a tc tbf rate, e.g. "10mbit". Empty = no shaping.
	QoSRate string `toml:"qos_rate"`
	// EgressRules is the extended L7 rule set (Cube parity: docs/guide/security-proxy.md).
	// When non-empty, it takes precedence over the flat allow/block domain lists.
	EgressRules []EgressRule `toml:"egress_rules"`
}

// EgressRule is one L7 egress rule, mirroring CubeSandbox's Rule/Match/Action.
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
}

// EgressInject mirrors Cube's Inject{header, format, secret} for credential injection.
type EgressInject struct {
	Header string `toml:"header" json:"header"`
	Format string `toml:"format" json:"format"` // e.g. "Bearer ${SECRET}", default "${SECRET}"
	Secret string `toml:"secret" json:"secret"`
}

// ToolRule is one row of the tool gateway decision matrix (plan.md §6.2).
// Every tool call from the agent is matched against these rules in order; the
// first match wins. A default-deny catch-all is auto-appended.
type ToolRule struct {
	// Name matches the tool name (exact, or "*" for wildcard).
	Name string `toml:"name"`
	// Action is one of: allow, constrain, approve, deny.
	Action string `toml:"action"`
	// Effect records what the rule governs — informational, used in audit.
	Effect string `toml:"effect"`
	// Reason is surfaced to the agent on deny/approve.
	Reason string `toml:"reason"`
}

// BudgetSpec is the hard resource/cost ceiling (plan.md §9.2 Budget).
type BudgetSpec struct {
	// MaxWallTime is the absolute wall-clock cap; on expiry the lifecycle FSM
	// moves the task to Destroy with reason "timeout".
	MaxWallTime string `toml:"max_wall_time"`
	// MaxTokens caps total LLM tokens consumed by the agent loop. 0 = unlimited.
	MaxTokens int `toml:"max_tokens"`
	// MaxNetworkMB caps total egress bytes (MB). 0 = unlimited.
	MaxNetworkMB int `toml:"max_network_mb"`
	// MaxCostMicroUSD caps total spend in micro-USD. 0 = unlimited.
	MaxCostMicroUSD int `toml:"max_cost_micro_usd"`
}

// ApprovalSpec defines the effect boundary — which tool actions require a human
// approval ticket before they may proceed (plan.md §10).
type ApprovalSpec struct {
	// RequiredFor lists tool actions that must pause for approval:
	// any of "send","delete","write-prod","pay","deploy","prod".
	RequiredFor []string `toml:"required_for"`
	// Notify is where approval requests are sent (currently logged + queued;
	// reserved for webhooks/IM).
	Notify string `toml:"notify"`
	// Timeout is how long an approval may pend before auto-deny.
	Timeout string `toml:"timeout"`
}

// ArtifactsSpec declares the sandbox's outputs (plan.md §5.3, §7).
// Only declared outputs may leave the sandbox; everything else stays inside.
type ArtifactsSpec struct {
	// Declared is the list of guest paths treated as outputs (diff/build/report).
	Declared []string `toml:"declared"`
	// RequireTestsPassed gates release on a green verifier run.
	RequireTestsPassed bool `toml:"require_tests_passed"`
	// BlockSecrets blocks release if a declared artifact diff contains secrets.
	BlockSecrets bool `toml:"block_secrets"`
}

// VolumeMount declares one persistent volume attachment. Mirrors
// sdk/go:VolumeMount{Name, Path, ReadOnly} and the TOML form:
//
//	[[volumes]]
//	name = "my-data"
//	path = "/workspace"
//	driver = "hostdir"   # optional, defaults to first registered plugin
//	read_only = true
type VolumeMount struct {
	Name     string `toml:"name" json:"name"`
	Path     string `toml:"path" json:"path"`
	Driver   string `toml:"driver" json:"driver"`
	ReadOnly bool   `toml:"read_only" json:"read_only"`
}

// LifecycleSpec is the task lifecycle policy (plan.md §8, §11).
type LifecycleSpec struct {
	// Paused starts the task in Suspended state (checkpoint-on-start).
	Paused bool `toml:"paused"`
	// MaxRetries is how many times the FSM may auto-retry Failed -> Provisioning.
	MaxRetries int `toml:"max_retries"`
	// OnAnomaly is the incident posture: "pause" (default) or "terminate".
	OnAnomaly string `toml:"on_anomaly"`
	// TTL is the task's overall lifetime; on expiry the task is Destroyed.
	TTL string `toml:"ttl"`
	// IdleTimeout triggers AutoPause: after this much idle time the task is
	// frozen (cgroup freeze) and moved to Suspended. Empty = disabled.
	// Mirrors CubeSandbox docs/guide/lifecycle.md: timeout + on_timeout=pause.
	IdleTimeout string `toml:"idle_timeout"`
	// AutoResume re-arms a Suspended task on the next API activity (any
	// /exec, /tasks/:id/*). Mirrors Cube's auto_resume.
	AutoResume bool `toml:"auto_resume"`
}

// --- loading & validation ---

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
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		// Unknown keys are a config-error signal (typo, stale field). Surface them.
		return nil, fmt.Errorf("spec: unknown keys in %s: %v", path, undecoded)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// LoadString parses and validates a TaskSpec from an in-memory TOML string.
// Used by the /api/tasks/load-spec endpoint when the UI submits content directly.
func LoadString(content string) (*TaskSpec, error) {
	var s TaskSpec
	md, err := toml.Decode(content, &s)
	if err != nil {
		return nil, fmt.Errorf("spec: parse: %w", err)
	}
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
	for i, vm := range s.Volumes {
		if vm.Name == "" {
			errs = append(errs, fmt.Errorf("spec: volumes[%d].name is required", i))
		}
		if vm.Path == "" {
			errs = append(errs, fmt.Errorf("spec: volumes[%d].path is required", i))
		} else if vm.Path[0] != '/' {
			errs = append(errs, fmt.Errorf("spec: volumes[%d].path %q must be absolute", i, vm.Path))
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
