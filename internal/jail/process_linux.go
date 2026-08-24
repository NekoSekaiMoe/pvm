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

// Environment markers used to hand the isolation plan to the re-exec'd
// stages. Go cannot run code between fork(2) and execve(2), so namespace
// setup is performed by re-executing this same binary with a marker set.
//
// The launch is a TWO-STAGE nsexec pipeline (the runc model), because every
// mount operation must happen with the right credentials in the right
// namespace:
//
//   - stage 1 (PVM_JAIL_STAGER): a fresh mount/IPC/UTS namespace with FULL
//     privileges (real root on the privileged leg; namespaced root via a
//     self uid-map on the unprivileged leg). It makes mounts private and
//     bind-mounts everything the workload needs (workload binary, system
//     trees, devices, volumes) into the jail rootfs using DIRECT paths —
//     no fd hand-over: mounts are namespace-scoped objects, an fd opened
//     in the parent namespace pins the PARENT's mount and fails check_mnt
//     when used as a bind source/target in the child (CI: EINVAL).
//   - stage 2 (PVM_JAIL_HELPER): cloned from stage 1 with
//     CLONE_NEWUSER|CLONE_NEWPID on the privileged rootless leg (uid/gid
//     maps written by stage 1, which is real root in init_user_ns). It
//     inherits stage 1's prepared mount table through copy_mnt_ns, then
//     self-binds the rootfs (a mount created in ITS OWN namespace, so
//     pivot_root accepts it), pivots, mounts the private /proc, applies
//     Landlock/capability/seccomp hardening and execs the workload as
//     pid 1 of the new PID namespace.
const (
	jailStagerEnvMarker = "PVM_JAIL_STAGER"
	jailHelperEnvMarker = "PVM_JAIL_HELPER"
	jailHelperEnvConfig = "PVM_JAIL_HELPER_CONFIG"
)

// jailHelperConfig is the JSON-serialized plan handed to both stages.
type jailHelperConfig struct {
	Rootfs  string          `json:"rootfs"`
	JailDir string          `json:"jail_dir"`
	Volumes []VolumeMapping `json:"volumes"`
	Target  string          `json:"target"`
	Args    []string        `json:"args"`
	// StageUserNS/StagePIDNS tell stage 2 which namespaces to enter when it
	// is cloned from stage 1, with UIDBase/UIDRangeSize the privileged
	// 65536-wide host uid range (internal/uidalloc). On the unprivileged
	// leg stage 1 already holds the self uid-map, so stage 2 only adds
	// NEWPID. On the degraded leg both are false (legacy mountns-only jail).
	StageUserNS  bool   `json:"stage_userns,omitempty"`
	StagePIDNS   bool   `json:"stage_pidns,omitempty"`
	UIDBase      uint32 `json:"uid_base,omitempty"`
	UIDRangeSize uint32 `json:"uid_range_size,omitempty"`
	// MountProc tells stage 2 to mount a private procfs at /proc after
	// pivot_root. It is set exactly when stage 2 gets CLONE_NEWPID, so the
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

// ConfigureProcessIsolation decorates the exec.Cmd with death-signals and
// isolation attributes for the two-stage launch.
//
// Namespace flag policy (rootless jail, TODO.md "[P1] Jail rootless 化"):
//
//   - Privileged + allocated uid range + usable userns (the target posture):
//     stage 1 = CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWUTS as REAL ROOT (mount
//     setup is most reliable with init_user_ns credentials); stage 2 adds
//     CLONE_NEWUSER (65536-wide map onto the container's uid range) and
//     CLONE_NEWPID. Namespaced root then holds zero capabilities in
//     init_user_ns: a compromised monitor cannot ptrace/kill/mount host
//     objects or even address host pids; seccomp and the capability
//     bounding set degrade to defense in depth.
//   - Unprivileged with usable userns: stage 1 additionally maps the
//     caller's uid (size 1) so it has the capabilities for the mount setup;
//     stage 2 adds CLONE_NEWPID.
//   - Degraded (privileged but no usable userns, or no uid range): stage 1
//     as above, stage 2 enters NO additional namespace — the legacy
//     mountns-only jail. jail.CheckSecurity reports this as the
//     "user-namespace" bypassed layer, gated by
//     security.allow_insecure_degraded.
//
// CLONE_NEWPID semantics for the monitor: UML installs handlers for every
// signal it uses (SIGALRM/SIGIO/SIGSEGV/...), so pid-1 "unhandled signals
// are ignored" semantics don't affect it; orphaned descendants reparent to
// it and its wait4 loop reaps them; UML poweroff is exit-based, so shutdown
// semantics are unchanged. cgroup membership is inherited from stage 1 (the
// pid the manager records), so limits cover the whole tree; stage 2 gets
// Pdeathsig=SIGKILL, so killing stage 1 takes the workload down with it.
func ConfigureProcessIsolation(cmd *exec.Cmd, j *JailEnvironment) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Always send SIGKILL to the stage-1 child if the parent manager exits.
	cmd.SysProcAttr.Pdeathsig = unix.SIGKILL

	privileged := unix.Geteuid() == 0
	caps := DetectHostCapabilities()
	// The isolation set applies when it can actually succeed at fork time:
	// privileged callers always may unshare; unprivileged callers need a
	// user namespace (CLONE_NEWNS without CAP_SYS_ADMIN would fail EPERM).
	if j.IsolationActive() {
		cfg := jailHelperConfig{
			Rootfs:             j.Rootfs,
			JailDir:            j.JailDir,
			Volumes:            j.Config.Volumes,
			Target:             cmd.Path,
			Args:               cmd.Args,
			EnforceHostSeccomp: j.Config.EnforceHostSeccomp,
		}
		switch {
		case !privileged && caps.HasUserNS:
			// Unprivileged leg: stage 1 needs the self uid-map to gain the
			// capabilities for its mount setup; stage 2 adds the pidns.
			cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER |
				syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS
			cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: unix.Getuid(), Size: 1},
			}
			cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
				{ContainerID: 0, HostID: unix.Getgid(), Size: 1},
			}
			cfg.StagePIDNS = true
			cfg.MountProc = true
		default:
			// Privileged legs (rootless hard boundary AND degraded):
			// stage 1 runs as real root in a fresh mountns.
			cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS
			if caps.HasUserNS && j.Config.UIDRangeSize > 0 {
				cfg.StageUserNS = true
				cfg.StagePIDNS = true
				cfg.MountProc = true
				cfg.UIDBase = j.Config.UIDBase
				cfg.UIDRangeSize = j.Config.UIDRangeSize
			}
			if os.Getenv(jailDisablePIDNSEnv) == "1" {
				cfg.StagePIDNS = false
				cfg.MountProc = false
			}
		}
		if err := wrapStage1(cmd, j, &cfg); err != nil {
			return err
		}
	}

	return nil
}

// jailSyncFDEnv names the inherited fd stage 1 blocks on until the manager
// finishes post-fork setup (cgroup membership). Kept OUT of ExtraFiles so
// the tap fd numbering (fd 3) is untouched; the fd is dupped high to stay
// clear of runtime fds.
const jailSyncFDEnv = "PVM_JAIL_SYNC_FD"

// jailDisablePIDNSEnv is a debug escape hatch for CI bisection:
// PVM_JAIL_DISABLE_PIDNS=1 drops the PID namespace (and the private /proc)
// from the launch, keeping everything else. It DEGRADES isolation (the
// monitor can see host processes if a procfs is reachable) — never set in
// production. Exists to answer "is the pidns the trigger?" for the vec0
// fd-transport wedge without a code change.
const jailDisablePIDNSEnv = "PVM_JAIL_DISABLE_PIDNS"

// wrapStage1 rewrites cmd so that, instead of the target binary, the current
// executable is re-exec'd as the stage-1 stager. Stage 1 runs with full
// privileges in a fresh mount namespace, so the direct executable path is
// always traversable — no fd hand-over is needed anywhere in the launch.
func wrapStage1(cmd *exec.Cmd, j *JailEnvironment, cfg *jailHelperConfig) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jail: locate executable for stage-1 re-exec: %w", err)
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("jail: encode stage config: %w", err)
	}

	// Launch-sync pipe: stage 1 blocks before cloning stage 2 until the
	// manager writes a byte (after cgroup.procs). Non-CLOEXEC inheritance
	// carries the read end through the stage-1 re-exec.
	syncR, syncW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("jail: create launch-sync pipe: %w", err)
	}
	syncFD, err := unix.FcntlInt(syncR.Fd(), unix.F_DUPFD, 400)
	syncR.Close()
	if err != nil {
		syncW.Close()
		return fmt.Errorf("jail: dup launch-sync fd: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(syncFD), unix.F_SETFD, 0); err != nil {
		unix.Close(syncFD)
		syncW.Close()
		return fmt.Errorf("jail: clear cloexec on launch-sync fd: %w", err)
	}
	j.syncW = syncW

	// Preserve the inherited environment: exec.Cmd falls back to os.Environ()
	// only while Env is nil, and the stages forward cmd.Env to the workload.
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(env,
		jailStagerEnvMarker+"=1",
		jailHelperEnvConfig+"="+string(blob),
		fmt.Sprintf("%s=%d", jailSyncFDEnv, syncFD),
	)
	cmd.Path = exe
	if len(cmd.Args) == 0 {
		cmd.Args = []string{exe}
	} else {
		cmd.Args = append([]string{exe}, cmd.Args...)
	}
	return nil
}
