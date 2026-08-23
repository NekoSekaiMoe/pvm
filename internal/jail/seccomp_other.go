//go:build !linux

package jail

var BlockedDangerousSyscalls = []string{
	"bpf", "io_uring_setup", "kexec_load", "reboot", "sys_chroot", "pivot_root", "mount", "unshare", "setns",
}

var UMLAllowedSyscalls = []string{
	"ptrace", "mmap", "read", "write", "open", "close", "socket",
}

func IsSyscallAllowed(name string) bool {
	return false
}

func IsSyscallDangerous(name string) bool {
	return true
}

func GetBlockedDangerousSyscalls() []string {
	return BlockedDangerousSyscalls
}

func GetUMLAllowedSyscalls() []string {
	return UMLAllowedSyscalls
}

func ApplyHostSeccompFilter() error {
	return nil
}
