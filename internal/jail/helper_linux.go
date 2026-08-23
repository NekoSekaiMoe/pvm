//go:build linux

package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// jailEntryPath is where the workload binary is bind-mounted inside the jail
// rootfs so it stays executable after pivot_root.
const jailEntryPath = "/pvm/entry"

// init implements the re-exec helper branch: when ConfigureProcessIsolation
// wrapped a command, the child process is this same binary with
// PVM_JAIL_HELPER=1 set. The branch runs before main() — inside the child's
// fresh mount/user namespaces — performs the filesystem isolation and then
// replaces the process image with the real workload via execve(2). Any
// failure is fatal: the workload must never start without the promised jail.
func init() {
	if os.Getenv(jailHelperEnvMarker) != "1" {
		return
	}
	if err := runJailHelper(); err != nil {
		fmt.Fprintf(os.Stderr, "jail helper: %v\n", err)
		os.Exit(1)
	}
	// runJailHelper only returns on error; a successful syscall.Exec never returns.
	os.Exit(0)
}

// runJailHelper executes the isolation plan and execs the target binary.
func runJailHelper() error {
	raw := os.Getenv(jailHelperEnvConfig)
	if raw == "" {
		return fmt.Errorf("missing %s", jailHelperEnvConfig)
	}
	var cfg jailHelperConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("decode helper config: %w", err)
	}
	if cfg.Rootfs == "" || cfg.Target == "" {
		return fmt.Errorf("helper config requires rootfs and target (got rootfs=%q target=%q)", cfg.Rootfs, cfg.Target)
	}

	allowed, err := setupJailFilesystem(&cfg)
	if err != nil {
		return err
	}

	// All host resources are bind-mounted now: close the hand-over fds so
	// they do not leak into the workload (caller-owned ExtraFiles like the
	// tap fd are untouched).
	closeHelperFDs(&cfg)

	// Landlock hardening runs after pivot_root so the allowed paths are the
	// in-jail views. Any failure aborts the launch.
	if err := ApplyLandlockLockdown(allowed); err != nil {
		return fmt.Errorf("landlock lockdown: %w", err)
	}

	// Scrub the helper markers before handing over to the real workload.
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, jailHelperEnvMarker+"=") || strings.HasPrefix(e, jailHelperEnvConfig+"=") {
			continue
		}
		env = append(env, e)
	}
	// Repoint HOME at a directory that exists inside the jail: UML's
	// make_umid() crashes the whole kernel on a missing $HOME (see
	// jailHomeEnv). This runs after pivot_root, so the existence check
	// sees the jail view, not the host's.
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
	// processes outside its own tree — the largest residual escape surface
	// of a privileged monitor. Irreversible across execve; failure aborts
	// the launch. Must run before exec, and pairs with the seccomp filter
	// (which cannot scope ptrace by target pid).
	if err := DropDangerousCapabilities(); err != nil {
		return fmt.Errorf("capability bounding-set drop: %w", err)
	}

	// Seccomp hardening is installed last when enabled: the filter survives
	// execve and constrains the workload for its entire lifetime. It must
	// come after setupJailFilesystem and the personality call (mount,
	// pivot_root and personality are all denied by the denylist filter).
	// When the config does not opt in (EnforceHostSeccomp=false) the install
	// is skipped entirely; when enabled, any failure aborts the launch.
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

// closeHelperFDs closes the hand-over fds recorded in the helper config.
func closeHelperFDs(cfg *jailHelperConfig) {
	for _, fd := range append([]int{cfg.ExeFD, cfg.TargetFD, cfg.RootfsFD, cfg.RootfsParentFD}, cfg.VolumeFDs...) {
		if fd > 0 {
			unix.Close(fd)
		}
	}
}

// setupJailFilesystem builds the jailed filesystem view from the helper
// config and pivots into it. It returns the post-pivot paths Landlock should
// keep accessible. Every mount / root-switch failure is fatal to the launch.
//
// Host-side sources are referenced ONLY through /proc/self/fd/N (see
// jailHelperConfig): the mapped uid inside the user namespace cannot
// necessarily traverse their ancestor directories.
func setupJailFilesystem(cfg *jailHelperConfig) ([]string, error) {
	rootfs := cfg.Rootfs
	if cfg.RootfsFD > 0 {
		rootfs = procFDPath(cfg.RootfsFD)
	}
	target := cfg.Target
	if cfg.TargetFD > 0 {
		target = procFDPath(cfg.TargetFD)
	}

	// Detach mount propagation from the host so none of the mounts below
	// leak into the parent mount namespace.
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return nil, fmt.Errorf("make host mounts private: %w", err)
	}

	// pivot_root requires new_root to be a mount point: bind the rootfs onto
	// itself.
	if err := unix.Mount(rootfs, rootfs, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return nil, fmt.Errorf("bind rootfs %s onto itself: %w", rootfs, err)
	}

	// roTargets collects the POST-PIVOT in-jail paths that must become
	// read-only. The remount runs after pivot_root on plain absolute paths:
	// inside a user namespace, remounting through a /proc/self/fd magic
	// link fails EINVAL (privileged CI leg), and MS_RDONLY on the initial
	// bind is silently ignored — hence the two-phase approach.
	var roTargets []string

	// The workload binary lives on the host filesystem; bind it into the
	// jail together with the read-only system trees its dynamic loader and
	// shared libraries live in, so execve still works after pivot_root.
	if err := bindFile(target, filepath.Join(rootfs, jailEntryPath)); err != nil {
		return nil, fmt.Errorf("bind workload binary %s: %w", cfg.Target, err)
	}
	roTargets = append(roTargets, jailEntryPath)
	allowed := []string{filepath.Dir(jailEntryPath)}
	for _, dir := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		if err := bindDir(dir, filepath.Join(rootfs, dir)); err != nil {
			return nil, fmt.Errorf("bind system directory %s: %w", dir, err)
		}
		allowed = append(allowed, dir)
		roTargets = append(roTargets, dir)
	}

	// Minimal device nodes a workload cannot function without.
	for _, dev := range []string{"null", "zero", "full", "random", "urandom"} {
		host := filepath.Join("/dev", dev)
		if fi, err := os.Stat(host); err != nil || fi.IsDir() {
			continue
		}
		if err := bindFile(host, filepath.Join(rootfs, "dev", dev)); err != nil {
			return nil, fmt.Errorf("bind device %s: %w", host, err)
		}
	}

	// Configured volumes: host path -> guest path inside the rootfs. Sources
	// are the inherited fds (procfd magic links), never the raw host paths.
	for i, v := range cfg.Volumes {
		if v.HostPath == "" || !filepath.IsAbs(v.GuestPath) {
			return nil, fmt.Errorf("invalid volume mapping %+v: need host path and absolute guest path", v)
		}
		src := v.HostPath
		if i < len(cfg.VolumeFDs) && cfg.VolumeFDs[i] > 0 {
			src = procFDPath(cfg.VolumeFDs[i])
		}
		dst := filepath.Join(rootfs, v.GuestPath)
		if err := bindPath(src, dst); err != nil {
			return nil, fmt.Errorf("bind volume %s -> %s: %w", v.HostPath, v.GuestPath, err)
		}
		allowed = append(allowed, v.GuestPath)
		if v.ReadOnly {
			roTargets = append(roTargets, v.GuestPath)
		}
	}

	// Jail working directories created by SetupJail. Only allowlist the
	// ones that actually exist in this rootfs: callers may construct a
	// JailEnvironment without SetupJail, and Landlock fails hard when an
	// allowed path cannot be opened after pivot_root.
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
	pivotRoot := rootfs
	if cfg.RootfsParentFD > 0 {
		// The rootfs fd was opened BEFORE the self-bind above, so its
		// /proc/self/fd path resolves to the ORIGINAL parent mount and
		// pivot_root would reject it ("not a mountpoint", EINVAL). Mount
		// crossing only happens when a walk ENTERS the mountpoint dentry
		// from its parent — re-walk openat(parent, base) after the
		// self-bind to land on the bind mount.
		bindF, err := os.Open(filepath.Join(procFDPath(cfg.RootfsParentFD), cfg.RootfsBaseName))
		if err != nil {
			return nil, fmt.Errorf("re-walk jail rootfs through parent fd: %w", err)
		}
		defer bindF.Close()
		pivotRoot = procFDPath(int(bindF.Fd()))
		oldRoot = filepath.Join(pivotRoot, ".pivot-old")
	}
	if err := unix.PivotRoot(pivotRoot, oldRoot); err != nil {
		return nil, fmt.Errorf("pivot_root into %s: %w", cfg.Rootfs, err)
	}
	if err := unix.Chdir("/"); err != nil {
		return nil, fmt.Errorf("chdir into new root: %w", err)
	}
	if err := unix.Unmount("/.pivot-old", unix.MNT_DETACH); err != nil {
		return nil, fmt.Errorf("unmount old root: %w", err)
	}
	_ = os.Remove("/.pivot-old")

	// Private procfs. Only mounted when the child got CLONE_NEWPID
	// (MountProc): the procfs then exposes the jail's own PID namespace
	// instead of the host process tree. Mounted after pivot_root so it
	// lands in the jail view; requires CAP_SYS_ADMIN in the child's user
	// namespace, which namespaced root has. Mount failures are fatal: a
	// workload promised a private /proc must not silently run without it.
	if cfg.MountProc {
		// SetupJail pre-creates <rootfs>/proc, but JailEnvironments built
		// by hand (tests, embedding callers) may lack it — create on demand.
		if err := os.MkdirAll("/proc", 0555); err != nil {
			return nil, fmt.Errorf("create /proc mountpoint: %w", err)
		}
		if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, ""); err != nil {
			return nil, fmt.Errorf("mount private /proc: %w", err)
		}
		allowed = append(allowed, "/proc")
	}

	// Apply the read-only remounts on plain post-pivot paths (see roTargets).
	for _, t := range roTargets {
		if err := remountReadOnly(t); err != nil {
			return nil, fmt.Errorf("make %s read-only: %w", t, err)
		}
	}

	return allowed, nil
}

// bindPath bind-mounts a host file or directory onto target inside the rootfs.
// Read-only is NOT applied here: see roTargets/remountReadOnly.
func bindPath(host, target string) error {
	fi, err := os.Stat(host)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return bindDir(host, target)
	}
	return bindFile(host, target)
}

// remountReadOnly switches a bind mount to read-only. It must be called with
// the POST-PIVOT in-jail path, never with a pre-pivot /proc/self/fd/-prefixed
// path: inside a user namespace, remounting through a procfs magic link fails
// with EINVAL (privileged CI leg, TestConfigureProcessIsolation_Execution).
func remountReadOnly(target string) error {
	// A read-only bind requires a separate remount pass; MS_RDONLY on the
	// initial bind is silently ignored.
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount read-only: %w", err)
	}
	return nil
}

func bindDir(host, target string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	return bindMount(host, target)
}

func bindFile(host, target string) error {
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
	return bindMount(host, target)
}

func bindMount(host, target string) error {
	// The bind itself is always created read-WRITE; read-only is applied
	// after pivot_root via remountReadOnly on the plain in-jail path (see
	// there for why the remount must not go through procfs magic links).
	return unix.Mount(host, target, "", unix.MS_BIND|unix.MS_REC, "")
}
