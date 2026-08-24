//go:build linux

package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// jailEntryPath is where the workload binary is bind-mounted inside the jail
// rootfs so it stays executable after pivot_root.
const jailEntryPath = "/pvm/entry"

// jailStage2Path is where stage 1 bind-mounts ITS OWN binary inside the
// rootfs, so stage 2 can re-exec it through an in-jail path. A direct host
// path would fail traversal: stage 2 runs as the container's mapped uid
// (host UIDBase), which cannot descend into permission-restricted
// workspaces (CI: /home/runner/work is 0750).
const jailStage2Path = "/pvm/stage2"

// init implements the re-exec stage branches: when ConfigureProcessIsolation
// wrapped a command, the child process is this same binary with a stage
// marker set. The branch runs before main() — inside the child's fresh
// namespaces. Any failure is fatal: the workload must never start without
// the promised jail.
func init() {
	if os.Getenv(jailStagerEnvMarker) == "1" {
		if err := runJailStager(); err != nil {
			fmt.Fprintf(os.Stderr, "jail stager: %v\n", err)
			dumpJailDebug()
			os.Exit(1)
		}
		// runJailStager never returns on success (it waits for stage 2 and
		// exits with its status).
		os.Exit(0)
	}
	if os.Getenv(jailHelperEnvMarker) == "1" {
		if err := runJailHelper(); err != nil {
			fmt.Fprintf(os.Stderr, "jail helper: %v\n", err)
			dumpJailDebug()
			os.Exit(1)
		}
		// runJailHelper only returns on error; a successful syscall.Exec never returns.
		os.Exit(0)
	}
}

// loadJailConfig decodes the shared stage plan from the environment.
func loadJailConfig() (*jailHelperConfig, error) {
	raw := os.Getenv(jailHelperEnvConfig)
	if raw == "" {
		return nil, fmt.Errorf("missing %s", jailHelperEnvConfig)
	}
	var cfg jailHelperConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("decode stage config: %w", err)
	}
	if cfg.Rootfs == "" || cfg.Target == "" {
		return nil, fmt.Errorf("stage config requires rootfs and target (got rootfs=%q target=%q)", cfg.Rootfs, cfg.Target)
	}
	return &cfg, nil
}

// scrubStageMarkers returns the environment without the stage markers, ready
// to be handed to the workload.
func scrubStageMarkers() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, jailStagerEnvMarker+"=") ||
			strings.HasPrefix(e, jailHelperEnvMarker+"=") ||
			strings.HasPrefix(e, jailHelperEnvConfig+"=") {
			continue
		}
		env = append(env, e)
	}
	return env
}

// dumpJailDebug dumps the namespace/credential state of the failing stage to
// stderr when PVM_JAIL_DEBUG is set. Mount EPERM/EINVAL failures inside user
// namespaces have half a dozen possible causes (capability sets, idmaps, LSM
// labels, mount flags), and reading them off the live process beats guessing.
func dumpJailDebug() {
	if os.Getenv("PVM_JAIL_DEBUG") == "" {
		return
	}
	dump := func(label, path string) {
		blob, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "jail debug: %s: %v\n", label, err)
			return
		}
		fmt.Fprintf(os.Stderr, "jail debug: %s:\n%s\n", label, strings.TrimRight(string(blob), "\n"))
	}
	fmt.Fprintf(os.Stderr, "jail debug: euid=%d egid=%d\n", unix.Geteuid(), unix.Getegid())
	dump("uid_map", "/proc/self/uid_map")
	dump("gid_map", "/proc/self/gid_map")
	// status carries CapEff/CapBnd/NoNewPrivs/Seccomp — trim to the lines
	// that matter to keep CI logs readable.
	if blob, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(blob), "\n") {
			if strings.HasPrefix(line, "Cap") || strings.HasPrefix(line, "NoNewPrivs") ||
				strings.HasPrefix(line, "Seccomp") || strings.HasPrefix(line, "Uid:") ||
				strings.HasPrefix(line, "Gid:") || strings.HasPrefix(line, "NStgid") ||
				strings.HasPrefix(line, "NSpid") {
				fmt.Fprintf(os.Stderr, "jail debug: status %s\n", line)
			}
		}
	}
	dump("attr/current (LSM label)", "/proc/self/attr/current")
	dump("mountinfo", "/proc/self/mountinfo")
}

// runJailStager is stage 1: full privileges in a fresh mount namespace. It
// isolates mount propagation, bind-mounts everything the workload needs into
// the jail rootfs (direct paths — it can traverse anything), and then clones
// stage 2 with the user/PID namespaces. Doing ALL mount work here is the
// point of the two-stage design: mount operations from inside a user
// namespace are subject to lockdown/LSM restrictions (CI: EPERM on
// propagation changes), while mounts are namespace-scoped objects that
// cannot be handed over via fds from the parent namespace.
func runJailStager() error {
	cfg, err := loadJailConfig()
	if err != nil {
		return err
	}

	// Detach mount propagation from the host so none of the mounts below
	// leak into the parent mount namespace.
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make host mounts private: %w", err)
	}

	if err := stageBinds(cfg); err != nil {
		return err
	}

	// Bind our own binary into the rootfs: stage 2 re-execs it through this
	// in-jail path (see jailStage2Path).
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable for stage-2 re-exec: %w", err)
	}
	if err := bindFile(exe, filepath.Join(cfg.Rootfs, jailStage2Path), true); err != nil {
		return fmt.Errorf("bind stage-2 binary %s: %w", exe, err)
	}

	// Clone stage 2 with the namespace flags the policy selected.
	child := exec.Command(filepath.Join(cfg.Rootfs, jailStage2Path))
	child.Env = append(scrubStageMarkers(),
		jailHelperEnvMarker+"=1",
		jailHelperEnvConfig+"="+os.Getenv(jailHelperEnvConfig),
	)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{
		// If stage 1 dies, the workload must not be orphaned.
		Pdeathsig: unix.SIGKILL,
		// CLONE_NEWNS is MANDATORY, not optional: without it stage 2 would
		// SHARE stage 1's mount namespace, whose owner is init_user_ns —
		// and may_mount() requires CAP_SYS_ADMIN in the mount namespace's
		// owner, which the mapped uid does not have (CI: every mount in
		// stage 2 EPERM'd). With NEWNS, copy_mnt_ns copies stage 1's
		// prepared tree into a fresh namespace owned by the new user
		// namespace, where stage 2's namespaced capabilities apply. It also
		// keeps stage 2's pivot_root from hijacking stage 1's view.
		Cloneflags: syscall.CLONE_NEWNS,
	}
	if cfg.StageUserNS {
		child.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
		child.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: int(cfg.UIDBase), Size: int(cfg.UIDRangeSize)},
		}
		child.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: int(cfg.UIDBase), Size: int(cfg.UIDRangeSize)},
		}
		// CRITICAL: clone(CLONE_NEWUSER) inherits the PARENT's kuid (host 0
		// for the privileged leg), which lies OUTSIDE the written map — the
		// child shows up as nobody and, decisively, execve's root capability
		// grant requires euid == make_kuid(new_userns, 0) == host UIDBase.
		// Without this Credential the child execs with ZERO capabilities and
		// every subsequent mount EPERMs (CI debug dump: Uid: 65534, CapEff: 0).
		// Go performs the setgid/setuid to these CONTAINER ids in the child
		// after the parent has written the uid/gid maps.
		child.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
	}
	if cfg.StagePIDNS {
		child.SysProcAttr.Cloneflags |= syscall.CLONE_NEWPID
	}
	if err := child.Start(); err != nil {
		return fmt.Errorf("start stage 2: %w", err)
	}
	// Forward the workload's exit status to the manager waiting on stage 1.
	err = child.Wait()
	if exitErr, ok := err.(*exec.ExitError); ok {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			os.Exit(ws.ExitStatus())
		}
		os.Exit(1)
	}
	return err
}

// stageBinds bind-mounts the workload binary, system trees, devices and
// configured volumes into the jail rootfs. Runs in stage 1 (full privileges,
// direct paths).
func stageBinds(cfg *jailHelperConfig) error {
	rootfs := cfg.Rootfs

	// The workload binary lives on the host filesystem; bind it into the
	// jail together with the read-only system trees its dynamic loader and
	// shared libraries live in, so execve still works after pivot_root.
	if err := bindFile(cfg.Target, filepath.Join(rootfs, jailEntryPath), true); err != nil {
		return fmt.Errorf("bind workload binary %s: %w", cfg.Target, err)
	}
	for _, dir := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		if err := bindDir(dir, filepath.Join(rootfs, dir), true); err != nil {
			return fmt.Errorf("bind system directory %s: %w", dir, err)
		}
	}

	// Minimal device nodes a workload cannot function without.
	for _, dev := range []string{"null", "zero", "full", "random", "urandom"} {
		host := filepath.Join("/dev", dev)
		if fi, err := os.Stat(host); err != nil || fi.IsDir() {
			continue
		}
		if err := bindFile(host, filepath.Join(rootfs, "dev", dev), false); err != nil {
			return fmt.Errorf("bind device %s: %w", host, err)
		}
	}

	// Configured volumes: host path -> guest path inside the rootfs.
	for _, v := range cfg.Volumes {
		if v.HostPath == "" || !filepath.IsAbs(v.GuestPath) {
			return fmt.Errorf("invalid volume mapping %+v: need host path and absolute guest path", v)
		}
		if err := bindPath(v.HostPath, filepath.Join(rootfs, v.GuestPath), v.ReadOnly); err != nil {
			return fmt.Errorf("bind volume %s -> %s: %w", v.HostPath, v.GuestPath, err)
		}
	}
	return nil
}

// runJailHelper is stage 2: it runs inside the user+PID namespaces selected
// by the policy (or no additional namespaces on the degraded leg), pivots
// into the rootfs stage 1 prepared, applies the hardening layers and execs
// the workload.
func runJailHelper() error {
	cfg, err := loadJailConfig()
	if err != nil {
		return err
	}

	allowed, err := pivotIntoJail(cfg)
	if err != nil {
		return err
	}

	// Landlock hardening runs after pivot_root so the allowed paths are the
	// in-jail views. Any failure aborts the launch.
	if err := ApplyLandlockLockdown(allowed); err != nil {
		return fmt.Errorf("landlock lockdown: %w", err)
	}

	// Repoint HOME at a directory that exists inside the jail: UML's
	// make_umid() crashes the whole kernel on a missing $HOME (see
	// jailHomeEnv). This runs after pivot_root, so the existence check
	// sees the jail view, not the host's.
	env := scrubStageMarkers()
	env = jailHomeEnv(env, func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.IsDir()
	})
	argv := cfg.Args
	if len(argv) == 0 {
		argv = []string{cfg.Target}
	}
	// The UML kernel's main() (arch/um/os-Linux/main.c) calls
	// personality(PER_LINUX | ADDR_NO_RANDOMIZE) and, when that CHANGES the
	// persona, re-execs itself via readlink("/proc/self/exe") + execve. When
	// the jail mounts a private /proc (MountProc) the readlink resolves and
	// the re-exec would work; when it does not (degraded mountns-only jail
	// without CLONE_NEWPID, where a mounted procfs would expose host
	// processes), the readlink gets ENOENT and the kernel dies instantly
	// with "readlink failure: No such file or directory" before printing a
	// single boot line. Pre-setting the exact persona the kernel asks for
	// makes it skip the re-exec entirely on BOTH paths (personality is
	// inherited across execve, which is the mechanism UML itself relies on).
	// This is fail-closed: without it the degraded-path workload is
	// guaranteed to die in the jail with a cryptic error.
	//   PER_LINUX = 0x0000, ADDR_NO_RANDOMIZE = 0x0040000 (linux/personality.h)
	if _, _, errno := unix.Syscall(unix.SYS_PERSONALITY, 0x0040000, 0, 0); errno != 0 {
		return fmt.Errorf("disable ASLR for jailed workload (personality ADDR_NO_RANDOMIZE): %w", errno)
	}

	// Capability bounding-set hardening: drop CAP_SYS_PTRACE & friends so
	// the workload (UML monitor) can never ptrace/signal/tamper with host
	// processes outside its own tree. Irreversible across execve; failure
	// aborts the launch. Defense in depth under the rootless hard boundary
	// (namespaces are the real containment), load-bearing on the degraded
	// leg.
	if err := DropDangerousCapabilities(); err != nil {
		return fmt.Errorf("capability bounding-set drop: %w", err)
	}

	// Seccomp hardening is installed last when enabled: the filter survives
	// execve and constrains the workload for its entire lifetime.
	if cfg.EnforceHostSeccomp {
		if err := ApplyHostSeccompFilter(); err != nil {
			return fmt.Errorf("seccomp filter: %w", err)
		}
	}

	if err := syscall.Exec(jailEntryPath, argv, env); err != nil {
		return fmt.Errorf("exec workload %s (in-jail %s): %w", cfg.Target, jailEntryPath, err)
	}
	return nil // unreachable
}

// pivotIntoJail self-binds the rootfs (creating the mountpoint pivot_root
// requires IN THIS NAMESPACE — a mount copied from stage 1's namespace could
// be lockdown-flagged and rejected), pivots into it, optionally mounts the
// private procfs, and returns the post-pivot paths Landlock should keep
// accessible. Every mount / root-switch failure is fatal to the launch.
func pivotIntoJail(cfg *jailHelperConfig) ([]string, error) {
	rootfs := cfg.Rootfs

	// pivot_root requires new_root to be a mount point: bind the rootfs
	// onto itself. Doing this in stage 2's own namespace (rather than
	// inheriting stage 1's self-bind) guarantees the mount is free of
	// cross-namespace lockdown flags.
	if err := unix.Mount(rootfs, rootfs, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return nil, fmt.Errorf("bind rootfs %s onto itself: %w", rootfs, err)
	}

	// Compute the Landlock allowlist from the in-jail view. Only allowlist
	// directories that actually exist in this rootfs: callers may construct
	// a JailEnvironment without SetupJail, and Landlock fails hard when an
	// allowed path cannot be opened after pivot_root.
	allowed := []string{filepath.Dir(jailEntryPath)}
	for _, dir := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
		if fi, err := os.Stat(filepath.Join(rootfs, dir)); err == nil && fi.IsDir() {
			allowed = append(allowed, dir)
		}
	}
	for _, v := range cfg.Volumes {
		allowed = append(allowed, v.GuestPath)
	}
	for _, sub := range []string{"volumes", "images", "sockets", "dev", "tmp"} {
		if fi, err := os.Stat(filepath.Join(rootfs, sub)); err == nil && fi.IsDir() {
			allowed = append(allowed, "/"+sub)
		}
	}

	// Switch root into the jail.
	oldRoot := filepath.Join(rootfs, ".pivot-old")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return nil, fmt.Errorf("create pivot_root mountpoint: %w", err)
	}
	if err := unix.PivotRoot(rootfs, oldRoot); err != nil {
		return nil, fmt.Errorf("pivot_root into %s: %w", rootfs, err)
	}
	if err := unix.Chdir("/"); err != nil {
		return nil, fmt.Errorf("chdir into new root: %w", err)
	}
	if err := unix.Unmount("/.pivot-old", unix.MNT_DETACH); err != nil {
		return nil, fmt.Errorf("unmount old root: %w", err)
	}
	_ = os.Remove("/.pivot-old")

	// Private procfs. Only mounted when stage 2 got CLONE_NEWPID
	// (MountProc): the procfs then exposes the jail's own PID namespace
	// instead of the host process tree. Mount failures are fatal: a
	// workload promised a private /proc must not silently run without it.
	if cfg.MountProc {
		if err := os.MkdirAll("/proc", 0555); err != nil {
			return nil, fmt.Errorf("create /proc mountpoint: %w", err)
		}
		if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, ""); err != nil {
			return nil, fmt.Errorf("mount private /proc: %w", err)
		}
		allowed = append(allowed, "/proc")
	}

	return allowed, nil
}

// bindPath bind-mounts a host file or directory onto target inside the rootfs.
func bindPath(host, target string, readOnly bool) error {
	fi, err := os.Stat(host)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return bindDir(host, target, readOnly)
	}
	return bindFile(host, target, readOnly)
}

func bindDir(host, target string, readOnly bool) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	return bindMount(host, target, readOnly)
}

func bindFile(host, target string, readOnly bool) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return bindMount(host, target, readOnly)
}

func bindMount(host, target string, readOnly bool) error {
	if err := unix.Mount(host, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	if readOnly {
		// A read-only bind requires a separate remount pass; MS_RDONLY on
		// the initial bind is silently ignored. Safe here: stage 1 runs
		// with full privileges on direct in-namespace paths.
		if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			return fmt.Errorf("remount read-only: %w", err)
		}
	}
	return nil
}
