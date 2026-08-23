//go:build !linux

package jail

var BlockedDangerousSyscalls = []string{
	"bpf", "io_uring_setup", "kexec_load", "reboot", "sys_chroot", "pivot_root", "mount", "unshare", "setns",
}

// IsSyscallAllowed mirrors the Linux denylist semantics: everything not
// flagged dangerous is allowed. The seccomp filter itself is Linux-only;
// this stub keeps shared tests compiling and passing everywhere.
func IsSyscallAllowed(name string) bool {
	return !IsSyscallDangerous(name)
}

// IsSyscallDangerous reports whether the named syscall is explicitly blocked as dangerous.
func IsSyscallDangerous(name string) bool {
	for _, s := range BlockedDangerousSyscalls {
		if s == name {
			return true
		}
	}
	return false
}

// GetBlockedDangerousSyscalls returns a copy of blocked dangerous syscalls,
// matching the Linux implementation's contract: callers must not be able to
// mutate the package-level backing array.
func GetBlockedDangerousSyscalls() []string {
	res := make([]string, len(BlockedDangerousSyscalls))
	copy(res, BlockedDangerousSyscalls)
	return res
}

// Classic BPF / seccomp constants, kept local because x/sys/unix does not
// expose seccomp return actions on non-Linux platforms.
const (
	bpfRetK           = 0x06       // BPF_RET | BPF_K
	seccompRetErrno   = 0x00050000 // SECCOMP_RET_ERRNO
	seccompErrnoEPERM = 1          // EPERM
)

// BuildUMLSeccompFilter returns a stub default-deny filter on non-Linux
// platforms. It is never installed, but keeps filter-structure call sites
// and shared tests compiling and passing everywhere.
func BuildUMLSeccompFilter() []SockFilter {
	return []SockFilter{
		{Code: bpfRetK, K: seccompRetErrno | seccompErrnoEPERM},
	}
}

func ApplyHostSeccompFilter() error {
	return nil
}
