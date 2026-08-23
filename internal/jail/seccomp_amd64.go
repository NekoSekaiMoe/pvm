//go:build linux && amd64

package jail

import "golang.org/x/sys/unix"

// archSpecificBlockedSyscalls lists dangerous syscalls that exist only on
// x86_64; appended to BlockedDangerousSyscalls in seccomp_linux.go.
var archSpecificBlockedSyscalls = []string{
	// Legacy x86 segment / I/O-port programming: pure host-kernel attack
	// surface, UML never uses them.
	"modify_ldt",
	"iopl",
	"ioperm",
	// create_module is the pre-finit_module loader (x86_64 nr 174).
	"create_module",
}

// getArchSyscallNumber resolves syscall names that exist only on x86_64.
func getArchSyscallNumber(name string) (int, bool) {
	switch name {
	case "modify_ldt":
		return unix.SYS_MODIFY_LDT, true
	case "iopl":
		return unix.SYS_IOPL, true
	case "ioperm":
		return unix.SYS_IOPERM, true
	case "create_module":
		return unix.SYS_CREATE_MODULE, true
	default:
		return 0, false
	}
}
