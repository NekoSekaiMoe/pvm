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
	argv := cfg.Args
	if len(argv) == 0 {
		argv = []string{cfg.Target}
	}
	if err := syscall.Exec(jailEntryPath, argv, env); err != nil {
		return fmt.Errorf("exec workload %s (in-jail %s): %w", cfg.Target, jailEntryPath, err)
	}
	return nil // unreachable
}

// setupJailFilesystem builds the jailed filesystem view from the helper
// config and pivots into it. It returns the post-pivot paths Landlock should
// keep accessible. Every mount / root-switch failure is fatal to the launch.
func setupJailFilesystem(cfg *jailHelperConfig) ([]string, error) {
	rootfs := cfg.Rootfs

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

	// The workload binary lives on the host filesystem; bind it into the
	// jail together with the read-only system trees its dynamic loader and
	// shared libraries live in, so execve still works after pivot_root.
	if err := bindFile(cfg.Target, filepath.Join(rootfs, jailEntryPath), true); err != nil {
		return nil, fmt.Errorf("bind workload binary %s: %w", cfg.Target, err)
	}
	allowed := []string{filepath.Dir(jailEntryPath)}
	for _, dir := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		if err := bindDir(dir, filepath.Join(rootfs, dir), true); err != nil {
			return nil, fmt.Errorf("bind system directory %s: %w", dir, err)
		}
		allowed = append(allowed, dir)
	}

	// Minimal device nodes a workload cannot function without.
	for _, dev := range []string{"null", "zero", "full", "random", "urandom"} {
		host := filepath.Join("/dev", dev)
		if fi, err := os.Stat(host); err != nil || fi.IsDir() {
			continue
		}
		if err := bindFile(host, filepath.Join(rootfs, "dev", dev), false); err != nil {
			return nil, fmt.Errorf("bind device %s: %w", host, err)
		}
	}

	// Configured volumes: host path -> guest path inside the rootfs.
	for _, v := range cfg.Volumes {
		if v.HostPath == "" || !filepath.IsAbs(v.GuestPath) {
			return nil, fmt.Errorf("invalid volume mapping %+v: need host path and absolute guest path", v)
		}
		target := filepath.Join(rootfs, v.GuestPath)
		if err := bindPath(v.HostPath, target, v.ReadOnly); err != nil {
			return nil, fmt.Errorf("bind volume %s -> %s: %w", v.HostPath, v.GuestPath, err)
		}
		allowed = append(allowed, v.GuestPath)
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
		// the initial bind is silently ignored.
		if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			return fmt.Errorf("remount read-only: %w", err)
		}
	}
	return nil
}
