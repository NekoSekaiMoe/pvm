//go:build linux

package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// Environment markers used to hand the mount/pivot_root plan to the re-exec'd
// jail helper (helper_linux.go). Go cannot run code between fork(2) and
// execve(2), so filesystem isolation inside the child's fresh mount namespace
// is performed by re-executing this same binary with the marker set; the
// helper branch then mounts, pivots into the rootfs, applies Landlock and
// finally execs the real workload.
const (
	jailHelperEnvMarker = "PVM_JAIL_HELPER"
	jailHelperEnvConfig = "PVM_JAIL_HELPER_CONFIG"
)

// jailHelperConfig is the JSON-serialized plan passed to the re-exec'd helper.
type jailHelperConfig struct {
	Rootfs  string          `json:"rootfs"`
	JailDir string          `json:"jail_dir"`
	Volumes []VolumeMapping `json:"volumes"`
	Target  string          `json:"target"`
	Args    []string        `json:"args"`
	// MountProc tells the helper to mount a private procfs at /proc after
	// pivot_root. It is set exactly when the child got CLONE_NEWPID, so the
	// procfs exposes only the jail's own process tree — safe to mount, and
	// it restores UML's readlink("/proc/self/exe") re-exec fallback.
	MountProc bool `json:"mount_proc"`
	// EnforceHostSeccomp mirrors Config.EnforceHostSeccomp: when false the
	// helper skips installing the host seccomp-bpf filter before exec'ing
	// the workload. Defaults (false) preserve the pre-toggle behavior only
	// for configs that never opted in; all first-class launch paths set it.
	EnforceHostSeccomp bool `json:"enforce_host_seccomp"`
}

// IsolationActive reports whether a launch through this environment would
// actually enter the jail (fresh mount namespace + pivot_root): it is the
// same predicate ConfigureProcessIsolation applies. Callers that rewrite
// host paths into in-jail bind-mount paths (rootfs image, /dev/net/tun,
// vhost-user socket) must consult this FIRST — when false, the workload
// keeps the host filesystem view and host paths must be left untouched.
func (j *JailEnvironment) IsolationActive() bool {
	if j == nil {
		return false
	}
	caps := DetectHostCapabilities()
	return caps.HasMountNS && (unix.Geteuid() == 0 || caps.HasUserNS)
}

// ConfigureProcessIsolation decorates the exec.Cmd with death-signals and isolation attributes.
//
// Namespace flag policy (rewritten for the rootless jail, TODO.md "[P1]
// Jail rootless 化"):
//
//   - CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS: pure isolation (private
//     mount view, SysV IPC key space, hostname/uts). The UML monitor uses
//     none of those host resources, so these namespaces are free.
//   - CLONE_NEWUSER: applied whenever a mapping is available.
//     Unprivileged caller: size-1 map of the caller's uid (rootless
//     operation, as before). Privileged caller with Config.UIDRangeSize>0:
//     65536-wide map onto the container's allocated host uid range — the
//     rootless HARD BOUNDARY. Namespaced root holds zero capabilities in
//     init_user_ns, so a compromised monitor cannot ptrace/kill/mount host
//     objects or even signal same-uid host daemons; seccomp and the
//     capability bounding set degrade to defense in depth. This requires
//     every runtime-privileged operation to have moved host-side already
//     (tap fd inheritance, manager-side cgroup writes, uid-range-owned jail
//     tree) — do not set UIDRangeSize before that plumbing exists.
//   - CLONE_NEWPID: applied together with CLONE_NEWUSER. The monitor
//     becomes pidns init: signals without a handler are ignored for pid 1,
//     but UML installs handlers for every signal it uses (SIGALRM/SIGIO/
//     SIGSEGV/...) so its semantics are unchanged; orphaned descendants
//     reparent to it and its existing wait4 loop reaps them; UML poweroff
//     is exit-based (machine_power_off() -> uml_cleanup() + halt_skas(),
//     no reboot(2)), so shutdown semantics are unchanged. Host tooling can
//     still kill it from an ancestor namespace. With a private pidns, the
//     jail can finally mount /proc without exposing host processes.
//
// Degraded mode: a privileged caller WITHOUT usable user namespaces (or
// with UIDRangeSize==0) keeps the legacy mountns-only jail — constraints,
// not a hard boundary. jail.CheckSecurity reports that as the
// "user-namespace" bypassed layer, gated by security.allow_insecure_degraded.
func ConfigureProcessIsolation(cmd *exec.Cmd, j *JailEnvironment) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Always send SIGKILL to the UML child if the parent manager exits
	cmd.SysProcAttr.Pdeathsig = unix.SIGKILL

	privileged := unix.Geteuid() == 0
	caps := DetectHostCapabilities()
	// The isolation set applies when it can actually succeed at fork time:
	// privileged callers always may unshare; unprivileged callers need a
	// user namespace (CLONE_NEWNS without CAP_SYS_ADMIN would fail EPERM).
	if j.IsolationActive() {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS
		mountProc := false
		switch {
		case !privileged && caps.HasUserNS:
			// Rootless: map the unprivileged caller to uid/gid 0 inside the
			// sandbox (single-id map, as before), plus the PID namespace.
			cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID
			cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: unix.Getuid(), Size: 1},
			}
			cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: unix.Getgid(), Size: 1},
			}
			mountProc = true
		case privileged && caps.HasUserNS && j.Config.UIDRangeSize > 0:
			// Rootless hard boundary for the privileged manager: 65536-wide
			// map onto the container's allocated host uid range + pidns.
			cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID
			cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: int(j.Config.UIDBase), Size: int(j.Config.UIDRangeSize)},
			}
			cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: int(j.Config.UIDBase), Size: int(j.Config.UIDRangeSize)},
			}
			mountProc = true
		}
		// Route the launch through the re-exec helper so the mounts,
		// pivot_root and Landlock hardening run inside the child's new
		// mount namespace before the real workload is exec'd.
		if err := wrapWithJailHelper(cmd, j, mountProc); err != nil {
			return err
		}
	}

	return nil
}

// wrapWithJailHelper rewrites cmd so that, instead of the target binary, the
// current executable is re-exec'd with the jail-helper marker set. The helper
// branch (helper_linux.go) performs the actual filesystem isolation and then
// execs the original target. Any isolation failure makes the child exit
// non-zero before the workload starts, so the error propagates to the caller
// waiting on the process.
func wrapWithJailHelper(cmd *exec.Cmd, j *JailEnvironment, mountProc bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jail: locate executable for re-exec helper: %w", err)
	}
	cfg := jailHelperConfig{
		Rootfs:             j.Rootfs,
		JailDir:            j.JailDir,
		Volumes:            j.Config.Volumes,
		Target:             cmd.Path,
		Args:               cmd.Args,
		MountProc:          mountProc,
		EnforceHostSeccomp: j.Config.EnforceHostSeccomp,
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("jail: encode helper config: %w", err)
	}

	// Preserve the inherited environment: exec.Cmd falls back to os.Environ()
	// only while Env is nil, and the helper forwards cmd.Env to the workload.
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(env,
		jailHelperEnvMarker+"=1",
		jailHelperEnvConfig+"="+string(blob),
	)
	cmd.Path = exe
	if len(cmd.Args) == 0 {
		cmd.Args = []string{exe}
	} else {
		cmd.Args = append([]string{exe}, cmd.Args...)
	}
	return nil
}
