//go:build linux

package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	// Inside the user namespace the mapped uid cannot necessarily even
	// TRAVERSE the ancestor directories of host paths (CI workspaces under
	// /home/runner/work are 0750, breaking both the re-exec of this binary
	// and every bind-mount source). So all host paths are opened by the
	// manager before the namespace clone and handed over as inherited fds;
	// the helper references them exclusively through /proc/self/fd/N, whose
	// magic-link resolution jumps straight to the dentry without an ancestor
	// walk. This is the "namespace 内只留 fd 操作" rule from the TODO design
	// sketch. A zero fd means "fall back to the path field" (used only by
	// tests that inject the helper config directly).
	ExeFD     int   `json:"exe_fd,omitempty"`
	TargetFD  int   `json:"target_fd,omitempty"`
	RootfsFD  int   `json:"rootfs_fd,omitempty"`
	// RootfsParentFD + RootfsBaseName exist for one namei subtlety: the
	// rootfs fd is opened BEFORE the helper self-binds the rootfs (pivot_root
	// requires new_root to be a mountpoint), so /proc/self/fd/<rootfs>
	// resolves to the ORIGINAL parent mount and pivot_root rejects it with
	// EINVAL ("not a mountpoint"). Mount crossing only happens when a walk
	// ENTERS the mountpoint dentry from its parent, so the helper re-walks
	// openat(RootfsParentFD, RootfsBaseName) AFTER the self-bind and pivots
	// through that fresh fd.
	RootfsParentFD int    `json:"rootfs_parent_fd,omitempty"`
	RootfsBaseName string `json:"rootfs_base_name,omitempty"`
	VolumeFDs      []int  `json:"volume_fds,omitempty"` // parallel to Volumes
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

// firstExtraFD is the fd number of ExtraFiles[0] in the child (os/exec
// contract: entry i becomes fd 3+i).
const firstExtraFD = 3

// procFDPath returns the /proc/self/fd/N path for an inherited fd. Magic
// links resolve straight to the open file description, so referencing host
// resources this way bypasses ancestor-directory permission checks that the
// mapped uid inside the user namespace might not pass.
func procFDPath(fd int) string {
	return fmt.Sprintf("/proc/self/fd/%d", fd)
}

// openBindSource opens a host path for hand-over into the jail. Files need
// O_RDONLY (an O_PATH fd cannot be exec'd and is weaker for mount sources);
// directories get O_DIRECTORY. The fd is what the helper bind-mounts
// through /proc/self/fd/N, bypassing ancestor-directory permission checks
// inside the user namespace.
func openBindSource(path string) (*os.File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	flag := os.O_RDONLY
	if fi.IsDir() {
		flag |= unix.O_DIRECTORY
	}
	return os.OpenFile(path, flag, 0)
}

// wrapWithJailHelper rewrites cmd so that, instead of the target binary, the
// current executable is re-exec'd with the jail-helper marker set. The helper
// branch (helper_linux.go) performs the actual filesystem isolation and then
// execs the original target. Any isolation failure makes the child exit
// non-zero before the workload starts, so the error propagates to the caller
// waiting on the process.
//
// ExtraFiles contract: fds the CALLER attached (tap fd via uml.KeyExtraFiles)
// keep their numbers (3..3+n-1); the jail appends its own hand-over fds
// (exe, target, rootfs, volumes) right after. All ExtraFiles are closed by
// the launcher after cmd.Start — the child holds its own duplicates.
func wrapWithJailHelper(cmd *exec.Cmd, j *JailEnvironment, mountProc bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jail: locate executable for re-exec helper: %w", err)
	}

	// Open every host path BEFORE the namespace clone (see jailHelperConfig).
	base := firstExtraFD + len(cmd.ExtraFiles)
	exeF, err := os.Open(exe) // O_RDONLY: O_PATH fds cannot be execve'd
	if err != nil {
		return fmt.Errorf("jail: open executable for re-exec: %w", err)
	}
	tgtF, err := openBindSource(cmd.Path)
	if err != nil {
		exeF.Close()
		return fmt.Errorf("jail: open workload %s: %w", cmd.Path, err)
	}
	rootF, err := openBindSource(j.Rootfs)
	if err != nil {
		exeF.Close()
		tgtF.Close()
		return fmt.Errorf("jail: open jail rootfs %s: %w", j.Rootfs, err)
	}
	volFs := make([]*os.File, 0, len(j.Config.Volumes))
	for _, v := range j.Config.Volumes {
		vf, err := openBindSource(v.HostPath)
		if err != nil {
			exeF.Close()
			tgtF.Close()
			rootF.Close()
			for _, f := range volFs {
				f.Close()
			}
			return fmt.Errorf("jail: open volume %s: %w", v.HostPath, err)
		}
		volFs = append(volFs, vf)
	}
	parentF, err := openBindSource(filepath.Dir(j.Rootfs))
	if err != nil {
		exeF.Close()
		tgtF.Close()
		rootF.Close()
		for _, f := range volFs {
			f.Close()
		}
		return fmt.Errorf("jail: open jail rootfs parent %s: %w", filepath.Dir(j.Rootfs), err)
	}

	cfg := jailHelperConfig{
		Rootfs:             j.Rootfs,
		JailDir:            j.JailDir,
		Volumes:            j.Config.Volumes,
		Target:             cmd.Path,
		Args:               cmd.Args,
		ExeFD:              base,
		TargetFD:           base + 1,
		RootfsFD:           base + 2,
		MountProc:          mountProc,
		EnforceHostSeccomp: j.Config.EnforceHostSeccomp,
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, exeF, tgtF, rootF)
	for i, vf := range volFs {
		cfg.VolumeFDs = append(cfg.VolumeFDs, base+3+i)
		cmd.ExtraFiles = append(cmd.ExtraFiles, vf)
	}
	cfg.RootfsParentFD = base + 3 + len(volFs)
	cfg.RootfsBaseName = filepath.Base(j.Rootfs)
	cmd.ExtraFiles = append(cmd.ExtraFiles, parentF)
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
	// Re-exec through the inherited fd, not the path: inside the new user
	// namespace the mapped uid may be unable to traverse the binary's
	// ancestor directories (CI workspaces are 0750). /proc/self/fd/N magic
	// links resolve straight to the file.
	cmd.Path = procFDPath(cfg.ExeFD)
	if len(cmd.Args) == 0 {
		cmd.Args = []string{exe}
	} else {
		cmd.Args = append([]string{exe}, cmd.Args...)
	}
	return nil
}
