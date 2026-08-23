//go:build linux

package securitytest

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"uml-container/internal/jail"
)

// =====================================================================
// ATTACK 13: seccomp filter structure integrity — dangerous host syscalls
// like bpf, io_uring, mount, unshare must NEVER be in the allowed set.
// =====================================================================

// TestAttack_SeccompFilterBlocksDangerousSyscalls depends on Linux seccomp
// semantics (jail.IsSyscallAllowed is backed by the Linux syscall table and
// is a stub on other platforms), so it lives in this Linux-only file.
func TestAttack_SeccompFilterBlocksDangerousSyscalls(t *testing.T) {
	dangerous := []string{"bpf", "io_uring_setup", "io_uring_enter", "mount", "unshare", "setns", "kexec_load", "reboot"}
	for _, d := range dangerous {
		d := d
		t.Run(d, func(t *testing.T) {
			if jail.IsSyscallAllowed(d) {
				t.Errorf("SECURITY: dangerous syscall %q is allowed by UML seccomp filter", d)
			}
		})
	}
}

// =====================================================================
// ATTACK 14: rootless hard boundary — a monitor wrapped in NEWUSER+NEWPID
// (TODO.md "[P1] Jail rootless 化") must not be able to signal, ptrace or
// even SEE host processes. Before this change the jail only constrained a
// real-root monitor (seccomp/capabilities); a jailbreak could kill or
// ptrace same-uid host processes. With the pid namespace the host pids are
// not even addressable (ESRCH), and with the user namespace any attempt
// that COULD name a host pid gets EPERM.
// =====================================================================

// TestAttack_JailedMonitorCannotTouchHostProcesses launches a jailed
// workload through the REAL jail path (ConfigureProcessIsolation, as the
// manager does) and has it attempt host-directed attacks from inside:
//
//	kill -TERM 2          — signal kthreadd (host pid 2)
//	cat /proc/2/cmdline   — read a host process's cmdline
//
// Under NEWPID the attack surface collapses to ESRCH (pid 2 does not exist
// in the namespace); the test also asserts the workload runs as pid 1,
// proving the pid namespace is actually active, and that the private /proc
// shows no host process. Runs on both CI legs: unprivileged (size-1 self
// map) and root (65536-wide range map, uid base 100000).
func TestAttack_JailedMonitorCannotTouchHostProcesses(t *testing.T) {
	caps := jail.DetectHostCapabilities()
	if !caps.HasUserNS || !caps.HasMountNS {
		t.Skip("host lacks user/mount namespaces")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh unavailable")
	}

	rootfs := t.TempDir()
	cfg := jail.Config{}
	if os.Geteuid() == 0 {
		// Mirror production SetupJail: the jail tree must be owned by the
		// container's uid range or the namespaced-root helper cannot create
		// the /proc mountpoint in it.
		cfg.UIDBase = 100000
		cfg.UIDRangeSize = 65536
		if err := os.Chown(rootfs, 100000, 100000); err != nil {
			t.Fatalf("chown jail rootfs into uid range: %v", err)
		}
	}
	env := &jail.JailEnvironment{Config: cfg, JailDir: rootfs, Rootfs: rootfs}

	const script = `
if [ $$ -eq 1 ]; then echo PIDNS_INIT_OK; else echo PIDNS_MISSING pid=$$; fi
kill -TERM 2 2>/dev/null || echo SIGNAL_HOST_PID_DENIED
cat /proc/2/cmdline >/dev/null 2>&1 || echo PROC_HOST_PID_INVISIBLE
`
	cmd := exec.Command("/bin/sh", "-c", script)
	if err := jail.ConfigureProcessIsolation(cmd, env); err != nil {
		t.Fatalf("ConfigureProcessIsolation: %v", err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if os.Geteuid() != 0 {
			t.Skipf("unprivileged namespace execution not permitted in this environment: %v, output: %s", err, out)
		}
		t.Fatalf("privileged jailed launch failed: %v, output: %s", err, out)
	}
	for _, want := range []string{"PIDNS_INIT_OK", "SIGNAL_HOST_PID_DENIED", "PROC_HOST_PID_INVISIBLE"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("SECURITY: expected %q in jailed workload output, got:\n%s", want, out)
		}
	}
}
