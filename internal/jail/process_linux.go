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
}

// ConfigureProcessIsolation decorates the exec.Cmd with death-signals and isolation attributes.
//
// The UML monitor is a host-side process-tree supervisor, not a leaf workload:
// it clones and ptraces every guest process and must keep vanilla signal and
// wait() semantics with the process tree around it. The flag policy below
// keeps only namespaces that cannot alter that supervision contract:
//
//   - CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS: pure isolation (private
//     mount view, SysV IPC key space, hostname/uts). The UML monitor uses
//     none of those host resources, so these namespaces are free.
//   - CLONE_NEWUSER (+ uid/gid mappings): rootless operation only. Its
//     purpose is to let an UNPRIVILEGED caller act as uid 0 inside the
//     sandbox. When the manager already runs as real root (umlctl start
//     under sudo, the agentpvm service), a user namespace strictly REMOVES
//     capabilities: namespaced root holds no capabilities in init_user_ns,
//     so host resources that real root could touch (/dev/net/tun TUNSETIFF,
//     cgroup v2 delegation, root-owned 0600 files) become EPERM. Never wrap
//     a privileged monitor in one.
//   - CLONE_NEWPID is never applied to the monitor. Making the monitor PID 1
//     of a PID namespace changes the semantics of the whole supervision
//     tree: signals without an explicit handler are ignored by pidns init,
//     orphaned processes reparent to it, and host tooling can only stop it
//     with SIGKILL from an ancestor namespace (pid_namespaces(7)). The guest
//     already runs inside UML's own virtual PID space — a host pidns around
//     the monitor adds no containment while breaking the supervision
//     contract. (UML poweroff is exit-based — machine_power_off() ->
//     uml_cleanup() + halt_skas(), no reboot(2) — so dropping CLONE_NEWPID
//     also keeps shutdown semantics on the plain-process path they were
//     designed for.)
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
	if j != nil && caps.HasMountNS && (privileged || caps.HasUserNS) {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS
		// Rootless only: map the unprivileged caller to uid/gid 0 inside
		// the sandbox. See the policy comment above for why a privileged
		// caller must NOT be wrapped in a user namespace.
		if !privileged && caps.HasUserNS {
			cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
			cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: unix.Getuid(), Size: 1},
			}
			cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: unix.Getgid(), Size: 1},
			}
		}
		// Route the launch through the re-exec helper so the mounts,
		// pivot_root and Landlock hardening run inside the child's new
		// mount namespace before the real workload is exec'd.
		if err := wrapWithJailHelper(cmd, j); err != nil {
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
func wrapWithJailHelper(cmd *exec.Cmd, j *JailEnvironment) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jail: locate executable for re-exec helper: %w", err)
	}
	cfg := jailHelperConfig{
		Rootfs:  j.Rootfs,
		JailDir: j.JailDir,
		Volumes: j.Config.Volumes,
		Target:  cmd.Path,
		Args:    cmd.Args,
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
