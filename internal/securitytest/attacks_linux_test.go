//go:build linux

package securitytest

import (
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
		if jail.IsSyscallAllowed(d) {
			t.Errorf("SECURITY: dangerous syscall %q is allowed by UML seccomp filter", d)
		}
	}
}
