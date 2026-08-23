//go:build linux

package jail

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BlockedDangerousSyscalls contains host syscalls that must NEVER be accessible
// by the UML host process to prevent host-kernel tampering, un-jailing, or breakouts.
var BlockedDangerousSyscalls = []string{
	"bpf",
	"io_uring_setup",
	"io_uring_enter",
	"io_uring_register",
	"kexec_load",
	"kexec_file_load",
	"reboot",
	"sys_chroot",
	"pivot_root",
	"mount",
	"umount2",
	"unshare",
	"setns",
	"init_module",
	"finit_module",
	"delete_module",
	"keyctl",
	"add_key",
	"request_key",
	"perf_event_open",
	"userfaultfd",
}

// UMLAllowedSyscalls contains the safe subset of host syscalls required by the
// UML kernel process to manage guest tasks (ptrace/SKAS), emulate memory/pages (mmap/mprotect),
// handle signals, communicate via vector TAP/vhost-user, and perform jailed I/O.
var UMLAllowedSyscalls = []string{
	// Ptrace (UML SKAS guest syscall interception)
	"ptrace",

	// Memory allocation & page tables
	"mmap", "mprotect", "munmap", "brk", "mremap", "madvise", "msync", "mincore",

	// Signals & Interrupts
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "rt_sigsuspend", "kill", "tgkill", "tkill",

	// Processes & Scheduling
	"clone", "clone3", "futex", "exit", "exit_group", "set_tid_address", "set_robust_list", "get_robust_list", "rseq",
	"getpid", "getppid", "gettid", "getuid", "geteuid", "getgid", "getegid", "getgroups", "setgroups", "prctl", "uname", "getrandom",
	"sched_yield", "sched_getaffinity", "sched_setaffinity",

	// Final exec handoff: the jail helper installs the filter and then
	// execs the workload (seccomp filters survive execve).
	"execve",

	// Time
	"clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep", "gettimeofday",

	// File I/O & IPC
	"read", "write", "pread64", "pwrite64", "readv", "writev", "close", "lseek", "dup", "dup3", "pipe2",
	"pselect6", "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait",
	"eventfd2", "timerfd_create", "timerfd_settime", "timerfd_gettime", "signalfd4",

	// Sockets (TAP transport, vhost-user Unix domain sockets)
	"socket", "socketpair", "connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
	"getsockname", "getpeername", "getsockopt", "setsockopt",

	// Jailed Filesystem / HostFS
	"openat", "openat2", "newfstatat", "statx", "fstatfs", "statfs",
	"faccessat", "faccessat2", "readlinkat", "getcwd", "chdir", "fchdir",
	"mkdirat", "unlinkat", "renameat2", "linkat", "symlinkat", "fchmodat", "fchownat",
	"ftruncate", "fallocate", "fsync", "fdatasync", "sync", "getdents64", "fcntl", "ioctl",
}

// IsSyscallAllowed reports whether the named syscall is in the UML allowed set.
func IsSyscallAllowed(name string) bool {
	for _, s := range UMLAllowedSyscalls {
		if s == name {
			return true
		}
	}
	return false
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

// GetBlockedDangerousSyscalls returns a copy of blocked dangerous syscalls.
func GetBlockedDangerousSyscalls() []string {
	res := make([]string, len(BlockedDangerousSyscalls))
	copy(res, BlockedDangerousSyscalls)
	return res
}

// GetUMLAllowedSyscalls returns a copy of allowed UML syscalls.
func GetUMLAllowedSyscalls() []string {
	res := make([]string, len(UMLAllowedSyscalls))
	copy(res, UMLAllowedSyscalls)
	return res
}

// BuildUMLSeccompFilter compiles a Classic BPF filter for the host UML process.
// It returns the package-local SockFilter type (a mirror of unix.SockFilter)
// so the filter structure can be built and tested on non-Linux platforms.
func BuildUMLSeccompFilter() []SockFilter {
	// Standard BPF Seccomp filter layout:
	// 1. Validate Architecture (AUDIT_ARCH_X86_64 or AUDIT_ARCH_AARCH64)
	// 2. Load Syscall Number: BPF_LD | BPF_W | BPF_ABS, offset 0
	// 3. Jump and return ALLOW for allowed syscalls
	// 4. Return EPERM for all other syscalls
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		// Unsupported architecture: no AUDIT_ARCH_* constant to pin the
		// filter to. Building anyway with arch=0 would produce a DENY-ALL
		// filter (no real arch value equals 0, so every syscall falls into
		// the ERRNO branch). Return an empty filter instead: the emptiness
		// guard in ApplyHostSeccompFilter then refuses to install anything.
		return nil
	}

	filter := []SockFilter{
		// [0] Load architecture: [4]
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		// [1] If arch != expected, kill process or deny
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1, Jf: 0},
		// [2] Return ERRNO(EPERM)
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA)},
		// [3] Load syscall number: [0]
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}

	// For each allowed syscall emit a JEQ/ALLOW pair: on a match fall
	// through (Jt=0) to the SECCOMP_RET_ALLOW immediately below; on a
	// mismatch skip it (Jf=1) and keep checking the remaining rules.
	for _, name := range UMLAllowedSyscalls {
		nr, ok := getSyscallNumber(name)
		if !ok || nr < 0 {
			continue
		}
		filter = append(filter,
			SockFilter{
				Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
				K:    uint32(nr),
				Jt:   0, // match: execute the ALLOW instruction directly below
				Jf:   1, // mismatch: skip ALLOW, continue with the next rule
			},
			SockFilter{
				Code: unix.BPF_RET | unix.BPF_K,
				K:    unix.SECCOMP_RET_ALLOW,
			},
		)
	}

	// Default fallback: return ERRNO(EPERM)
	filter = append(filter, SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA),
	})

	return filter
}

// ApplyHostSeccompFilter installs the tailored BPF seccomp filter on the current thread/process.
func ApplyHostSeccompFilter() error {
	// Set PR_SET_NO_NEW_PRIVS to 1 (required before installing seccomp filter without CAP_SYS_ADMIN)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("seccomp: set no_new_privs: %w", err)
	}

	filter := BuildUMLSeccompFilter()
	if len(filter) == 0 {
		return fmt.Errorf("seccomp: empty filter")
	}
	raw := make([]unix.SockFilter, len(filter))
	for i, f := range filter {
		raw[i] = unix.SockFilter{Code: f.Code, Jt: f.Jt, Jf: f.Jf, K: f.K}
	}
	prog := unix.SockFprog{
		Len:    uint16(len(raw)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&raw[0])),
	}

	// SECCOMP_SET_MODE_FILTER = 1
	const seccompSetModeFilter = 1
	_, _, err := unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(seccompSetModeFilter),
		0,
		uintptr(unsafe.Pointer(&prog)),
	)
	// ENOSYS (kernel without seccomp-filter support) is a fail-closed
	// condition — the task would otherwise run unfiltered — not a success.
	if err != 0 {
		return fmt.Errorf("seccomp: install filter: %w", err)
	}
	return nil
}
