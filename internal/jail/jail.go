package jail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
	// Rootless hard boundary: a privileged manager wraps the monitor in
	// NEWUSER+NEWPID (TODO.md "[P1] Jail rootless 化"). A host without
	// usable user namespaces forces the fallback to the plain mountns jail —
	// constraints, not a hard boundary — so it is reported as its own
	// bypassed layer and gated by allow_insecure_degraded like the rest.
	if privileged && !caps.HasUserNS {
		bypassed = append(bypassed, "user-namespace")
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
		Details:        "all required host security baselines satisfied (seccomp, landlock, namespaces, user-namespace)",
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
	// UIDBase + UIDRangeSize select the rootless hard boundary for a
	// PRIVILEGED manager: when UIDRangeSize > 0 and the process runs as real
	// root, the monitor is placed in a user namespace mapping in-ns
	// [0, UIDRangeSize) onto host uids [UIDBase, UIDBase+UIDRangeSize), plus
	// a PID namespace (see ConfigureProcessIsolation). Namespaced root holds
	// zero capabilities in init_user_ns, so ptrace/kill/mount of host objects
	// is namespace-contained rather than seccomp-constrained. All
	// runtime-privileged operations (tap attach, cgroup writes) must have
	// been moved host-side by the caller before enabling this. The base comes
	// from the centralized allocation table (internal/uidalloc).
	// UIDRangeSize == 0 keeps the legacy mountns-only jail (degraded mode).
	UIDBase      uint32 `json:"uid_base,omitempty"`
	UIDRangeSize uint32 `json:"uid_range_size,omitempty"`
}

// JailEnvironment holds the created jail paths and configuration handles.
type JailEnvironment struct {
	Config  Config
	JailDir string
	Rootfs  string
	// syncW is the write end of the launch-sync pipe created by
	// ConfigureProcessIsolation. Stage 1 blocks on the read end until the
	// manager has finished post-fork setup (cgroup.procs) — see SignalReady.
	syncW *os.File
	// grants records host files whose ownership/mode was temporarily
	// widened for the namespaced monitor (GrantMonitorRW); Cleanup restores
	// the original owner/mode before releasing the jail directory.
	grants []fileGrant
}

// fileGrant is one recorded GrantMonitorRW mutation awaiting restore.
type fileGrant struct {
	path string
	uid  int
	gid  int
	mode os.FileMode
}

// GrantMonitorRW ensures the namespaced monitor (fixed host creds
// uidBase:gidBase) can open hostPath read-write, recording every change so
// Cleanup can restore the file exactly. The monitor only ever opens the
// in-jail BIND of the file (stage 1 binds it as real root), so ancestor
// traversal never matters — the inode's own DAC is the entire check, and
// for a foreign-owned image the monitor is "other", which on a typical
// 0644 image means READ-ONLY. UML's ubd then silently degrades to a
// read-only device: the guest rootfs mounts ro, /etc/resolv.conf cannot be
// written, DNS via getaddrinfo fails ("wget: bad address") and the boot
// limps to INIT_DONE rc=99 (CI run 8856, both arches, after every
// networking theory had been eliminated by the pidns bisect).
//
// chown is used instead of setfacl/loop devices: zero external
// dependencies, and Cleanup restores the original owner (and mode, if the
// owner-write bit had to be added), so the mutation is temporary by
// construction. Callers must treat rw images as per-container for the
// duration of the jail (two concurrent jails would chown the same inode
// back and forth — share via read-only/ephemeral images instead).
func (j *JailEnvironment) GrantMonitorRW(hostPath string, uidBase, gidBase uint32) error {
	fi, err := os.Stat(hostPath)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect owner of %s", hostPath)
	}
	mode := fi.Mode().Perm()
	// Monitor creds are exactly uidBase:gidBase; anything short of an
	// owner match falls through to the world bits.
	if st.Uid == uidBase && mode&0o200 != 0 || mode&0o006 == 0o006 {
		return nil
	}
	grant := fileGrant{path: hostPath, uid: int(st.Uid), gid: int(st.Gid), mode: mode}
	if err := os.Chown(hostPath, int(uidBase), int(gidBase)); err != nil {
		return fmt.Errorf("chown %s into container uid range: %w", hostPath, err)
	}
	if mode&0o200 == 0 {
		if err := os.Chmod(hostPath, mode|0o200); err != nil {
			_ = os.Chown(hostPath, grant.uid, grant.gid)
			return fmt.Errorf("add owner-write to %s: %w", hostPath, err)
		}
	}
	j.grants = append(j.grants, grant)
	return nil
}

// SignalReady releases stage 1 to clone stage 2. The manager MUST call this
// after Launcher.Start returns and cgroup membership has been written for
// the stage-1 pid: cgroup membership is inherited at fork(), so a stage 2
// cloned BEFORE the write would live outside the container's limits (a real
// race — stage 1 reaches the clone in microseconds). Idempotent and
// nil-safe; a no-op when no sync pipe exists (isolation inactive).
func (j *JailEnvironment) SignalReady() {
	if j == nil || j.syncW == nil {
		return
	}
	_, _ = j.syncW.Write([]byte{1})
	_ = j.syncW.Close()
	j.syncW = nil
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
		// /tmp, not os.TempDir(): stage 2 resolves the rootfs by DIRECT path
		// as the container's mapped uid, so every ancestor must be
		// traversable by it. /tmp is 1777 by POSIX convention; $TMPDIR may
		// point into permission-restricted workspaces (CI: /home/runner/work
		// is 0750, which broke the rootless launch).
		cfg.BaseDir = filepath.Join(string(os.PathSeparator), "tmp", "pvm-jails", cfg.TaskID)
	}

	jailDir := filepath.Join(cfg.BaseDir, "root")
	if err := os.MkdirAll(jailDir, 0700); err != nil {
		return nil, fmt.Errorf("jail: create jail root: %w", err)
	}

	// Create subdirectories for jail mounts. "proc" is the mountpoint for
	// the private procfs the helper mounts when the monitor gets its own
	// PID namespace (ConfigureProcessIsolation).
	for _, sub := range []string{"volumes", "images", "sockets", "dev", "tmp", "proc"} {
		if err := os.MkdirAll(filepath.Join(jailDir, sub), 0700); err != nil {
			return nil, fmt.Errorf("jail: create jail subfolder %s: %w", sub, err)
		}
	}

	// Rootless hard boundary: the jail tree must be owned by the container's
	// host uid range, or the namespaced-root workload (host uid UIDBase)
	// cannot write its own /tmp, mountpoints or physmem files once DAC is
	// real (host-root-owned 0700 dirs map to overflowuid inside the userns).
	// The BaseDir ancestors get the same treatment: stage 2 walks the
	// rootfs path as the mapped uid, so pvm-jails must be traversable (0755)
	// and the per-task dir owned by the range. Harmless in degraded mode
	// (real root bypasses DAC) and skipped for the unprivileged leg, where
	// the caller already owns what it created.
	if os.Geteuid() == 0 && cfg.UIDRangeSize > 0 {
		// Stage 2 walks the rootfs path as the mapped uid, so EVERY ancestor
		// of BaseDir must grant execute (traversal). Custom BaseDir values
		// (tests under t.TempDir()) can sit beneath 0700 directories.
		// Traversal-only: ADD execute bits, never touch read bits — this
		// must not weaken directories we did not create.
		for d := filepath.Dir(cfg.BaseDir); d != "/" && d != "."; d = filepath.Dir(d) {
			fi, statErr := os.Stat(d)
			if statErr != nil {
				break
			}
			if fi.Mode().Perm()&0o111 == 0o111 {
				continue
			}
			_ = os.Chmod(d, fi.Mode().Perm()|0o111)
		}
		if err := os.Chown(cfg.BaseDir, int(cfg.UIDBase), int(cfg.UIDBase)); err != nil {
			return nil, fmt.Errorf("jail: chown jail base dir to uid range base %d: %w", cfg.UIDBase, err)
		}
		_ = os.Chmod(cfg.BaseDir, 0711)
		if err := os.Chown(jailDir, int(cfg.UIDBase), int(cfg.UIDBase)); err != nil {
			return nil, fmt.Errorf("jail: chown jail root to uid range base %d: %w", cfg.UIDBase, err)
		}
		for _, sub := range []string{"volumes", "images", "sockets", "dev", "tmp", "proc"} {
			if err := os.Chown(filepath.Join(jailDir, sub), int(cfg.UIDBase), int(cfg.UIDBase)); err != nil {
				return nil, fmt.Errorf("jail: chown jail subfolder %s: %w", sub, err)
			}
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
	if j == nil {
		return nil
	}
	// Closing the sync pipe unreleased makes stage 1 see EOF and abort the
	// launch (fail closed: no workload without cgroup membership confirmed).
	if j.syncW != nil {
		_ = j.syncW.Close()
		j.syncW = nil
	}
	// Restore host files widened by GrantMonitorRW (best-effort, reverse
	// order) before the jail directory goes away.
	for i := len(j.grants) - 1; i >= 0; i-- {
		g := j.grants[i]
		_ = os.Chmod(g.path, g.mode)
		_ = os.Chown(g.path, g.uid, g.gid)
	}
	j.grants = nil
	if j.Config.BaseDir == "" {
		return nil
	}
	return os.RemoveAll(j.Config.BaseDir)
}
