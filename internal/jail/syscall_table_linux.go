//go:build linux

package jail

import "golang.org/x/sys/unix"

// getSyscallNumber maps the names used by the seccomp DENYLIST
// (BlockedDangerousSyscalls + arch extras) and the argument-filtered
// syscalls (ioctl, prlimit64) to their kernel numbers on the build
// architecture. Names that don't resolve are skipped by
// BuildUMLSeccompFilter — for a denylist that is a fail-OPEN gap, so
// TestSeccomp_BlockedSyscallsResolvable pins every entry on every
// supported architecture.
func getSyscallNumber(name string) (int, bool) {
	switch name {
	// Argument-filtered syscalls
	case "ioctl":
		return unix.SYS_IOCTL, true
	case "prlimit64":
		return unix.SYS_PRLIMIT64, true

	// Host-kernel attack surface
	case "bpf":
		return unix.SYS_BPF, true
	case "io_uring_setup":
		return unix.SYS_IO_URING_SETUP, true
	case "io_uring_enter":
		return unix.SYS_IO_URING_ENTER, true
	case "io_uring_register":
		return unix.SYS_IO_URING_REGISTER, true
	case "perf_event_open":
		return unix.SYS_PERF_EVENT_OPEN, true
	case "userfaultfd":
		return unix.SYS_USERFAULTFD, true

	// Kernel image / module loading
	case "kexec_load":
		return unix.SYS_KEXEC_LOAD, true
	case "kexec_file_load":
		return unix.SYS_KEXEC_FILE_LOAD, true
	case "init_module":
		return unix.SYS_INIT_MODULE, true
	case "finit_module":
		return unix.SYS_FINIT_MODULE, true
	case "delete_module":
		return unix.SYS_DELETE_MODULE, true

	// Namespace / root manipulation
	case "reboot":
		return unix.SYS_REBOOT, true
	case "sys_chroot":
		return unix.SYS_CHROOT, true
	case "pivot_root":
		return unix.SYS_PIVOT_ROOT, true
	case "mount":
		return unix.SYS_MOUNT, true
	case "umount2":
		return unix.SYS_UMOUNT2, true
	case "unshare":
		return unix.SYS_UNSHARE, true
	case "setns":
		return unix.SYS_SETNS, true

	// Kernel keyring
	case "keyctl":
		return unix.SYS_KEYCTL, true
	case "add_key":
		return unix.SYS_ADD_KEY, true
	case "request_key":
		return unix.SYS_REQUEST_KEY, true

	// Host wall-clock
	case "settimeofday":
		return unix.SYS_SETTIMEOFDAY, true
	case "clock_settime":
		return unix.SYS_CLOCK_SETTIME, true
	case "adjtimex":
		return unix.SYS_ADJTIMEX, true
	case "clock_adjtime":
		return unix.SYS_CLOCK_ADJTIME, true

	// Cross-process memory
	case "process_vm_readv":
		return unix.SYS_PROCESS_VM_READV, true
	case "process_vm_writev":
		return unix.SYS_PROCESS_VM_WRITEV, true

	// Host-global administrative knobs
	case "acct":
		return unix.SYS_ACCT, true
	case "swapon":
		return unix.SYS_SWAPON, true
	case "swapoff":
		return unix.SYS_SWAPOFF, true
	case "syslog":
		return unix.SYS_SYSLOG, true
	case "quotactl":
		return unix.SYS_QUOTACTL, true
	case "quotactl_fd":
		return unix.SYS_QUOTACTL_FD, true
	case "vhangup":
		return unix.SYS_VHANGUP, true

	// New mount API
	case "fsopen":
		return unix.SYS_FSOPEN, true
	case "fsconfig":
		return unix.SYS_FSCONFIG, true
	case "fsmount":
		return unix.SYS_FSMOUNT, true
	case "fspick":
		return unix.SYS_FSPICK, true
	case "move_mount":
		return unix.SYS_MOVE_MOUNT, true
	case "open_tree":
		return unix.SYS_OPEN_TREE, true
	case "mount_setattr":
		return unix.SYS_MOUNT_SETATTR, true

	// File-handle I/O (Landlock path-scope bypass)
	case "name_to_handle_at":
		return unix.SYS_NAME_TO_HANDLE_AT, true
	case "open_by_handle_at":
		return unix.SYS_OPEN_BY_HANDLE_AT, true

	// Cross-process fd-based signalling/memory
	case "pidfd_open":
		return unix.SYS_PIDFD_OPEN, true
	case "pidfd_send_signal":
		return unix.SYS_PIDFD_SEND_SIGNAL, true
	case "process_madvise":
		return unix.SYS_PROCESS_MADVISE, true
	case "process_mrelease":
		return unix.SYS_PROCESS_MRELEASE, true

	default:
		// Architecture-specific numbers (e.g. modify_ldt/iopl exist only on
		// x86_64). Defined in seccomp_<goarch>.go so this file compiles on
		// every Linux target.
		return getArchSyscallNumber(name)
	}
}
