//go:build linux && arm64

package jail

// archSpecificBlockedSyscalls is empty on arm64: the legacy x86-only
// dangerous syscalls (modify_ldt, iopl, ioperm, create_module) do not
// exist in the asm-generic syscall table.
var archSpecificBlockedSyscalls []string

// getArchSyscallNumber resolves no extra names on arm64.
func getArchSyscallNumber(name string) (int, bool) {
	return 0, false
}
