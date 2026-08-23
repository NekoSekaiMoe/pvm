package jail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SecurityReport contains the evaluation results of host security mechanisms.
type SecurityReport struct {
	Degraded       bool     `json:"degraded"`
	BypassedLayers []string `json:"bypassed_layers"`
	Details        string   `json:"details"`
}

// HostCapabilities tracks available host-side isolation primitives.
type HostCapabilities struct {
	HasLandlock bool   `json:"has_landlock"`
	HasUserNS   bool   `json:"has_userns"`
	HasSeccomp  bool   `json:"has_seccomp"`
	HasMountNS  bool   `json:"has_mountns"`
	Details     string `json:"details"`
}

var (
	capMu      sync.RWMutex // guards cachedCaps against concurrent test injection
	capOnce    sync.Once
	cachedCaps HostCapabilities
)

// DetectHostCapabilities probes the host kernel and environment for security primitives.
func DetectHostCapabilities() HostCapabilities {
	capOnce.Do(func() {
		capMu.Lock()
		defer capMu.Unlock()
		cachedCaps = probeHostCapabilities()
	})
	capMu.RLock()
	defer capMu.RUnlock()
	return cachedCaps
}

// ResetHostCapabilitiesForTest allows unit tests to inject simulated capability states.
//
// This is a test hook that intentionally remains part of the production API:
// cross-package tests (internal/container, internal/integrationtest,
// internal/securitytest) import the jail package and therefore cannot see a
// jail-internal export_test.go helper. It must not be called by production code.
func ResetHostCapabilitiesForTest(caps *HostCapabilities) {
	capOnce.Do(func() {}) // Disarm capOnce so DetectHostCapabilities will not overwrite cachedCaps
	capMu.Lock()
	defer capMu.Unlock()
	if caps == nil {
		cachedCaps = probeHostCapabilities()
	} else {
		cachedCaps = *caps
	}
}

// CheckSecurity evaluates host capabilities against required security baselines.
// When allowDegraded is false (default), it FAILS CLOSED if any critical security
// mechanism is unavailable. When allowDegraded is true, it returns a report with
// the list of bypassed security layers.
func CheckSecurity(allowDegraded bool, enforceSeccomp, enforceLandlock bool) (*SecurityReport, error) {
	caps := DetectHostCapabilities()
	var bypassed []string

	if enforceSeccomp && !caps.HasSeccomp {
		bypassed = append(bypassed, "seccomp-bpf")
	}
	if enforceLandlock && !caps.HasLandlock {
		bypassed = append(bypassed, "landlock-lsm")
	}
	// The namespace-isolation baseline must mirror what
	// ConfigureProcessIsolation actually requires (process_linux.go): a
	// usable mount namespace plus either a privileged caller or user
	// namespaces to unshare rootless.
	privileged := os.Geteuid() == 0
	if !caps.HasMountNS || (!privileged && !caps.HasUserNS) {
		bypassed = append(bypassed, "namespace-isolation")
	}

	if len(bypassed) > 0 {
		if !allowDegraded {
			return nil, fmt.Errorf(
				"security jail: fail-closed: host security baseline unmet (missing: %s). "+
					"Task execution rejected. Pass '--insecure-allow-degraded' or set "+
					"'security.allow_insecure_degraded = true' in TaskSpec to explicitly bypass",
				strings.Join(bypassed, ", "),
			)
		}
		return &SecurityReport{
			Degraded:       true,
			BypassedLayers: bypassed,
			Details:        fmt.Sprintf("bypassed host security layers: %s", strings.Join(bypassed, ", ")),
		}, nil
	}

	return &SecurityReport{
		Degraded:       false,
		BypassedLayers: nil,
		Details:        "all required host security baselines satisfied (seccomp, landlock, namespaces)",
	}, nil
}

// VolumeMapping defines a host-to-guest directory mapping.
type VolumeMapping struct {
	HostPath  string `json:"host_path"`
	GuestPath string `json:"guest_path"`
	ReadOnly  bool   `json:"read_only"`
}

// Config specifies the jail parameters for a container or task.
type Config struct {
	TaskID                string          `json:"task_id"`
	BaseDir               string          `json:"base_dir"` // jail root directory
	Volumes               []VolumeMapping `json:"volumes"`
	ImageFiles            []string        `json:"image_files"`
	SocketFiles           []string        `json:"socket_files"`
	AllowInsecureDegraded bool            `json:"allow_insecure_degraded"`
	EnforceHostSeccomp    bool            `json:"enforce_host_seccomp"`
	EnforceLandlock       bool            `json:"enforce_landlock"`
}

// JailEnvironment holds the created jail paths and configuration handles.
type JailEnvironment struct {
	Config  Config
	JailDir string
	Rootfs  string
}

// SetupJail creates the in-process Gofer jail structure for the task.
func SetupJail(cfg Config) (*JailEnvironment, error) {
	if cfg.TaskID == "" {
		return nil, fmt.Errorf("jail: task ID is required")
	}
	// The task ID becomes a path component of the default BaseDir; reject
	// path separators and traversal components so an attacker-controlled ID
	// cannot escape the jail root. The exact value "." is rejected too:
	// filepath.Join would collapse it away, pointing the jail at the shared
	// pvm-jails parent directory itself.
	if cfg.TaskID == "." || strings.ContainsAny(cfg.TaskID, "/\\") || strings.Contains(cfg.TaskID, "..") {
		return nil, fmt.Errorf("jail: invalid task ID %q: must not contain path separators or '..' traversal components", cfg.TaskID)
	}
	if cfg.BaseDir == "" {
		cfg.BaseDir = filepath.Join(os.TempDir(), "pvm-jails", cfg.TaskID)
	}

	jailDir := filepath.Join(cfg.BaseDir, "root")
	if err := os.MkdirAll(jailDir, 0700); err != nil {
		return nil, fmt.Errorf("jail: create jail root: %w", err)
	}

	// Create subdirectories for jail mounts
	for _, sub := range []string{"volumes", "images", "sockets", "dev", "tmp"} {
		if err := os.MkdirAll(filepath.Join(jailDir, sub), 0700); err != nil {
			return nil, fmt.Errorf("jail: create jail subfolder %s: %w", sub, err)
		}
	}

	return &JailEnvironment{
		Config:  cfg,
		JailDir: jailDir,
		Rootfs:  jailDir,
	}, nil
}

// Cleanup removes the jail directory and releases any held resources.
func (j *JailEnvironment) Cleanup() error {
	if j == nil || j.Config.BaseDir == "" {
		return nil
	}
	return os.RemoveAll(j.Config.BaseDir)
}
