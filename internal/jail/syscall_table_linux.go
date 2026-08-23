//go:build linux

package jail

import "golang.org/x/sys/unix"

func getSyscallNumber(name string) (int, bool) {
	switch name {
	case "ptrace":
		return unix.SYS_PTRACE, true
	case "mmap":
		return unix.SYS_MMAP, true
	case "mprotect":
		return unix.SYS_MPROTECT, true
	case "munmap":
		return unix.SYS_MUNMAP, true
	case "brk":
		return unix.SYS_BRK, true
	case "mremap":
		return unix.SYS_MREMAP, true
	case "madvise":
		return unix.SYS_MADVISE, true
	case "msync":
		return unix.SYS_MSYNC, true
	case "mincore":
		return unix.SYS_MINCORE, true
	case "rt_sigaction":
		return unix.SYS_RT_SIGACTION, true
	case "rt_sigprocmask":
		return unix.SYS_RT_SIGPROCMASK, true
	case "rt_sigreturn":
		return unix.SYS_RT_SIGRETURN, true
	case "sigaltstack":
		return unix.SYS_SIGALTSTACK, true
	case "rt_sigsuspend":
		return unix.SYS_RT_SIGSUSPEND, true
	case "kill":
		return unix.SYS_KILL, true
	case "tgkill":
		return unix.SYS_TGKILL, true
	case "tkill":
		return unix.SYS_TKILL, true
	case "clone":
		return unix.SYS_CLONE, true
	case "clone3":
		return unix.SYS_CLONE3, true
	case "futex":
		return unix.SYS_FUTEX, true
	case "exit":
		return unix.SYS_EXIT, true
	case "exit_group":
		return unix.SYS_EXIT_GROUP, true
	case "set_tid_address":
		return unix.SYS_SET_TID_ADDRESS, true
	case "set_robust_list":
		return unix.SYS_SET_ROBUST_LIST, true
	case "get_robust_list":
		return unix.SYS_GET_ROBUST_LIST, true
	case "rseq":
		return unix.SYS_RSEQ, true
	case "getpid":
		return unix.SYS_GETPID, true
	case "getppid":
		return unix.SYS_GETPPID, true
	case "gettid":
		return unix.SYS_GETTID, true
	case "getuid":
		return unix.SYS_GETUID, true
	case "geteuid":
		return unix.SYS_GETEUID, true
	case "getgid":
		return unix.SYS_GETGID, true
	case "getegid":
		return unix.SYS_GETEGID, true
	case "getgroups":
		return unix.SYS_GETGROUPS, true
	case "setgroups":
		return unix.SYS_SETGROUPS, true
	case "prctl":
		return unix.SYS_PRCTL, true
	case "uname":
		return unix.SYS_UNAME, true
	case "getrandom":
		return unix.SYS_GETRANDOM, true
	case "sched_yield":
		return unix.SYS_SCHED_YIELD, true
	case "sched_getaffinity":
		return unix.SYS_SCHED_GETAFFINITY, true
	case "sched_setaffinity":
		return unix.SYS_SCHED_SETAFFINITY, true
	case "execve":
		return unix.SYS_EXECVE, true
	case "clock_gettime":
		return unix.SYS_CLOCK_GETTIME, true
	case "clock_getres":
		return unix.SYS_CLOCK_GETRES, true
	case "clock_nanosleep":
		return unix.SYS_CLOCK_NANOSLEEP, true
	case "nanosleep":
		return unix.SYS_NANOSLEEP, true
	case "gettimeofday":
		return unix.SYS_GETTIMEOFDAY, true
	case "read":
		return unix.SYS_READ, true
	case "write":
		return unix.SYS_WRITE, true
	case "pread64":
		return unix.SYS_PREAD64, true
	case "pwrite64":
		return unix.SYS_PWRITE64, true
	case "readv":
		return unix.SYS_READV, true
	case "writev":
		return unix.SYS_WRITEV, true
	case "close":
		return unix.SYS_CLOSE, true
	case "lseek":
		return unix.SYS_LSEEK, true
	case "dup":
		return unix.SYS_DUP, true
	case "dup3":
		return unix.SYS_DUP3, true
	case "pipe2":
		return unix.SYS_PIPE2, true
	case "pselect6":
		return unix.SYS_PSELECT6, true
	case "ppoll":
		return unix.SYS_PPOLL, true
	case "epoll_create1":
		return unix.SYS_EPOLL_CREATE1, true
	case "epoll_ctl":
		return unix.SYS_EPOLL_CTL, true
	case "epoll_pwait":
		return unix.SYS_EPOLL_PWAIT, true
	case "eventfd2":
		return unix.SYS_EVENTFD2, true
	case "timerfd_create":
		return unix.SYS_TIMERFD_CREATE, true
	case "timerfd_settime":
		return unix.SYS_TIMERFD_SETTIME, true
	case "timerfd_gettime":
		return unix.SYS_TIMERFD_GETTIME, true
	case "signalfd4":
		return unix.SYS_SIGNALFD4, true
	case "socket":
		return unix.SYS_SOCKET, true
	case "socketpair":
		return unix.SYS_SOCKETPAIR, true
	case "connect":
		return unix.SYS_CONNECT, true
	case "bind":
		return unix.SYS_BIND, true
	case "listen":
		return unix.SYS_LISTEN, true
	case "accept":
		return unix.SYS_ACCEPT, true
	case "accept4":
		return unix.SYS_ACCEPT4, true
	case "sendto":
		return unix.SYS_SENDTO, true
	case "recvfrom":
		return unix.SYS_RECVFROM, true
	case "sendmsg":
		return unix.SYS_SENDMSG, true
	case "recvmsg":
		return unix.SYS_RECVMSG, true
	case "shutdown":
		return unix.SYS_SHUTDOWN, true
	case "getsockname":
		return unix.SYS_GETSOCKNAME, true
	case "getpeername":
		return unix.SYS_GETPEERNAME, true
	case "getsockopt":
		return unix.SYS_GETSOCKOPT, true
	case "setsockopt":
		return unix.SYS_SETSOCKOPT, true
	case "openat":
		return unix.SYS_OPENAT, true
	case "openat2":
		return unix.SYS_OPENAT2, true
	case "newfstatat":
		return unix.SYS_NEWFSTATAT, true
	case "statx":
		return unix.SYS_STATX, true
	case "fstat":
		return unix.SYS_FSTAT, true
	case "fstatfs":
		return unix.SYS_FSTATFS, true
	case "statfs":
		return unix.SYS_STATFS, true
	case "faccessat":
		return unix.SYS_FACCESSAT, true
	case "faccessat2":
		return unix.SYS_FACCESSAT2, true
	case "readlinkat":
		return unix.SYS_READLINKAT, true
	case "getcwd":
		return unix.SYS_GETCWD, true
	case "getrlimit":
		return unix.SYS_GETRLIMIT, true
	case "prlimit64":
		return unix.SYS_PRLIMIT64, true
	case "wait4":
		return unix.SYS_WAIT4, true
	case "chdir":
		return unix.SYS_CHDIR, true
	case "fchdir":
		return unix.SYS_FCHDIR, true
	case "mkdirat":
		return unix.SYS_MKDIRAT, true
	case "unlinkat":
		return unix.SYS_UNLINKAT, true
	case "renameat2":
		return unix.SYS_RENAMEAT2, true
	case "linkat":
		return unix.SYS_LINKAT, true
	case "symlinkat":
		return unix.SYS_SYMLINKAT, true
	case "fchmodat":
		return unix.SYS_FCHMODAT, true
	case "fchownat":
		return unix.SYS_FCHOWNAT, true
	case "ftruncate":
		return unix.SYS_FTRUNCATE, true
	case "fallocate":
		return unix.SYS_FALLOCATE, true
	case "fsync":
		return unix.SYS_FSYNC, true
	case "fdatasync":
		return unix.SYS_FDATASYNC, true
	case "sync":
		return unix.SYS_SYNC, true
	case "getdents64":
		return unix.SYS_GETDENTS64, true
	case "fcntl":
		return unix.SYS_FCNTL, true
	case "ioctl":
		return unix.SYS_IOCTL, true
	default:
		// Architecture-specific numbers (e.g. arch_prctl exists only on
		// x86_64). Defined in seccomp_<goarch>.go so this file compiles on
		// every Linux target.
		return getArchSyscallNumber(name)
	}
}
