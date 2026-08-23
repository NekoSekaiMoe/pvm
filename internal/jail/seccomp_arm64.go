//go:build linux && arm64

package jail

// archSpecificAllowedSyscalls is empty on arm64: TLS setup uses the
// tpidr_el0 MSR instruction (no syscall), so nothing analogous to
// x86_64's arch_prctl is needed.
var archSpecificAllowedSyscalls []string

// getArchSyscallNumber resolves no extra names on arm64.
func getArchSyscallNumber(name string) (int, bool) {
	return 0, false
}
