//go:build linux && amd64

package jail

import "golang.org/x/sys/unix"

// archSpecificAllowedSyscalls lists syscalls that exist (and are needed)
// only on x86_64; appended to UMLAllowedSyscalls in seccomp_linux.go.
var archSpecificAllowedSyscalls = []string{
	// x86_64 glibc sets up its TLS block via arch_prctl(ARCH_SET_FS) —
	// both ld.so (dynamic binaries) and __libc_setup_tls (static). There
	// is no fallback: when the filter denies it, the workload dies with
	// "Fatal glibc error: Cannot allocate TLS block" before main().
	// Process-local state only; no host impact.
	"arch_prctl",
}

// getArchSyscallNumber resolves syscall names that exist only on x86_64.
func getArchSyscallNumber(name string) (int, bool) {
	switch name {
	case "arch_prctl":
		return unix.SYS_ARCH_PRCTL, true
	default:
		return 0, false
	}
}
