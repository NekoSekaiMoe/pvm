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
//
// POLICY MODEL: this filter is a DENYLIST (fail-open), not an allowlist.
// History: the original allowlist died by a thousand cuts — the filter is
// installed before execve, so it constrains ld.so and glibc startup too, and
// every missing entry killed the boot one CI round-trip at a time:
//   - fstat (ld.so stats every shared object) -> "cannot stat shared object"
//   - arch_prctl (x86_64 TLS setup) -> "Cannot allocate TLS block"
//   - getrlimit/prlimit64 (UML set_stklim) -> "getrlimit: Operation not permitted"
//   - timer_create/settime (guest tick) -> boot wedges in calibrate_delay
//   - restart_syscall (resume of signal-interrupted blocking syscalls)
//
// UML + glibc need a long tail of host syscalls; enumerating them is
// unmaintainable. The containment contract instead rests on:
//  1. this denylist (host-kernel attack surface and breakout primitives),
//  2. second-stage argument filters on ioctl and prlimit64 (multiplexed /
//     dual-use syscalls stay restricted — see buildIoctlArgFilter and
//     buildPrlimit64ArgFilter),
//  3. the other jail layers: no_new_privs, mount/IPC/UTS namespaces,
//     pivot_root into a minimal rootfs, and Landlock path lockdown.
//
// When adding to this list, prefer syscalls that are genuinely dangerous from
// a jailed SUPERVISOR process (the UML kernel is ptrace-master of its guests;
// guest syscalls never reach this filter). Anything the kernel returns EPERM
// for here must be something UML legitimately never calls.
var BlockedDangerousSyscalls = []string{
	// Host-kernel attack surface / eBPF & I/O ring programming
	"bpf",
	"io_uring_setup",
	"io_uring_enter",
	"io_uring_register",
	"perf_event_open",
	"userfaultfd", // dirty-cow-class exploitation primitive; UML never uses it

	// Kernel image / module loading
	"kexec_load",
	"kexec_file_load",
	"init_module",
	"finit_module",
	"delete_module",

	// Breakout primitives: namespace and root manipulation
	"reboot",
	"sys_chroot",
	"pivot_root",
	"mount",
	"umount2",
	"unshare",
	"setns",

	// Kernel keyring manipulation
	"keyctl",
	"add_key",
	"request_key",

	// Host wall-clock manipulation (a jail must not shift host time)
	"settimeofday",
	"clock_settime",
	"adjtimex",
	"clock_adjtime",

	// Cross-process host memory access (UML ptraces only its OWN children)
	"process_vm_readv",
	"process_vm_writev",

	// Host-global administrative knobs
	"acct",
	"swapon",
	"swapoff",
	"syslog",      // kernel ring buffer read/clear
	"quotactl",    // filesystem quota control
	"quotactl_fd", // fd-based quota variant
	"vhangup",     // hang up all host terminals

	// New mount API (the modern replacement for mount(2)): blocking only
	// "mount"/"pivot_root" while leaving fsopen/fsmount/move_mount open
	// would make the mount ban decorative. UML never uses any of these.
	"fsopen",
	"fsconfig",
	"fsmount",
	"fspick",
	"move_mount",
	"open_tree",
	"mount_setattr",
	// (fsinfo was never merged into the mainline kernel — nothing to block)

	// File-handle I/O bypasses Landlock: Landlock scopes PATHS, and
	// open_by_handle_at takes an inode handle instead. The jail's bind
	// mounts share superblocks with the host directories they mirror, so a
	// handle obtained (or brute-forced) inside the jail opens files on the
	// host superblock — a textbook jail escape when running as real root
	// with CAP_DAC_READ_SEARCH. UML never uses handle-based I/O.
	"name_to_handle_at",
	"open_by_handle_at",

	// Cross-process signalling/memory via fds: the jail has no PID
	// namespace (see ConfigureProcessIsolation), so these reach EVERY host
	// process. UML signals its guests with kill/tgkill/wait4 (allowed —
	// its children are known to it) and never uses the pidfd/process_m*
	// families.
	"pidfd_open",
	"pidfd_send_signal",
	"process_madvise",
	"process_mrelease",

	// NOTE (accepted residual risk, same as the old allowlist): clone/clone3
	// are allowed without flag filtering. clone3 takes a flags STRUCT POINTER
	// which seccomp cannot dereference, so CLONE_NEW* cannot be blocked
	// there; filtering only clone would be security theater. A child in fresh
	// namespaces still inherits this filter + no_new_privs + Landlock.
}

// IsSyscallAllowed reports whether the named syscall is permitted by the
// denylist filter — i.e. everything not flagged dangerous (and not restricted
// by an argument filter) is allowed.
func IsSyscallAllowed(name string) bool {
	return !IsSyscallDangerous(name)
}

// IsSyscallDangerous reports whether the named syscall is explicitly blocked as dangerous.
func IsSyscallDangerous(name string) bool {
	for _, s := range blockedSyscallsEffective {
		if s == name {
			return true
		}
	}
	return false
}

// GetBlockedDangerousSyscalls returns a copy of blocked dangerous syscalls.
func GetBlockedDangerousSyscalls() []string {
	res := make([]string, len(blockedSyscallsEffective))
	copy(res, blockedSyscallsEffective)
	return res
}

// blockedSyscallsEffective is the runtime denylist: the portable dangerous
// set plus per-architecture extras (e.g. modify_ldt/iopl on x86_64), defined
// in seccomp_<goarch>.go.
var blockedSyscallsEffective = append(append([]string{},
	BlockedDangerousSyscalls...), archSpecificBlockedSyscalls...)

// BuildUMLSeccompFilter compiles a Classic BPF filter for the host UML process.
// It returns the package-local SockFilter type (a mirror of unix.SockFilter)
// so the filter structure can be built and tested on non-Linux platforms.
//
// Denylist layout:
//  1. Validate architecture (AUDIT_ARCH_X86_64 or AUDIT_ARCH_AARCH64);
//     mismatch -> ERRNO(EPERM)
//  2. Load syscall number
//  3. Each dangerous syscall: match -> ERRNO(EPERM)
//  4. ioctl / prlimit64: second-stage argument filters (match decides by
//     arguments; mismatch falls through)
//  5. Default: ALLOW
func BuildUMLSeccompFilter() []SockFilter {
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

	eperm := SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA),
	}

	filter := []SockFilter{
		// [0] Load architecture: [4]
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		// [1] If arch != expected, deny
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1, Jf: 0},
		// [2] Return ERRNO(EPERM)
		eperm,
		// [3] Load syscall number: [0]
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}

	// Dangerous syscalls: match -> EPERM, mismatch -> keep checking.
	for _, name := range blockedSyscallsEffective {
		nr, ok := getSyscallNumber(name)
		if !ok || nr < 0 {
			// A blocked name that does not resolve would silently stay
			// ALLOWED (fail-open gap). TestSeccomp_BlockedSyscallsResolvable
			// pins every entry to a real number on each supported arch.
			continue
		}
		filter = append(filter,
			SockFilter{
				Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
				K:    uint32(nr),
				Jt:   0, // match: execute the EPERM directly below
				Jf:   1, // mismatch: skip EPERM, continue with the next rule
			},
			eperm,
		)
	}

	// Dual-use syscalls keep their second-stage argument filters. On a
	// syscall-number match the block decides ALLOW/EPERM by arguments; on a
	// mismatch the block is skipped and evaluation continues.
	for _, name := range []string{"ioctl", "prlimit64"} {
		nr, ok := getSyscallNumber(name)
		if !ok || nr < 0 {
			continue
		}
		if name == "ioctl" {
			filter = append(filter, buildIoctlArgFilter(uint32(nr))...)
		} else {
			filter = append(filter, buildPrlimit64ArgFilter(uint32(nr))...)
		}
	}

	// Denylist default: allow everything else.
	filter = append(filter, SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_ALLOW,
	})

	return filter
}

// seccompArg1LowOffset is the byte offset of the low 32 bits of args[1]
// (the ioctl request) in struct seccomp_data {nr@0, arch@4, ip@8, args@16}.
// Both supported architectures (x86_64, aarch64) are little-endian, so the
// low word of the 64-bit argument sits at offset 24.
const seccompArg1LowOffset = 24

// 64-bit argument word offsets within struct seccomp_data (args start at
// offset 16; each 64-bit arg occupies a low word at 16+8*i and a high word
// at 16+8*i+4 on the little-endian x86_64/aarch64). Used by the prlimit64
// second-stage filter to compare the COMPLETE 64-bit argument values.
const (
	seccompArg0LowOffset  = 16 // prlimit64: pid (low word)
	seccompArg0HighOffset = 20 // prlimit64: pid (high word)
	seccompArg2LowOffset  = 32 // prlimit64: new_limit pointer (low word)
	seccompArg2HighOffset = 36 // prlimit64: new_limit pointer (high word)
)

// buildPrlimit64ArgFilter emits the two-stage rule for prlimit64: only
// read-only self-queries pass — pid must be 0 (the calling process) and
// new_limit must be NULL (nothing to set). Both arguments are compared as
// complete 64-bit values (low and high words each must be zero); the
// new_limit POINTER is compared, never dereferenced — seccomp filters
// cannot safely follow userspace pointers. The resource selector and
// old_limit output pointer are unrestricted: with new_limit == NULL the
// call cannot change anything. A nonzero pid (another process's limits) or
// a non-NULL new_limit (a limit raise, e.g. escaping RLIMIT_NOFILE /
// RLIMIT_NPROC confinement) falls to ERRNO(EPERM).
//
// Block layout: [JEQ nr] then per check [LD word; JEQ 0 (fall through on
// match, skip to the trailing EPERM on mismatch)], then ALLOW, then EPERM.
// The initial JEQ's Jf skips the entire block (2 insns per check + ALLOW +
// EPERM).
func buildPrlimit64ArgFilter(nr uint32) []SockFilter {
	eperm := SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA),
	}
	allow := SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}

	// Words that must all be zero for the call to be allowed.
	zeroWordOffsets := []uint32{
		seccompArg0LowOffset,  // pid low
		seccompArg0HighOffset, // pid high
		seccompArg2LowOffset,  // new_limit low
		seccompArg2HighOffset, // new_limit high
	}

	block := []SockFilter{
		{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			K:    nr,
			Jt:   0,                                 // match: fall through to the argument checks
			Jf:   uint8(2*len(zeroWordOffsets) + 2), // mismatch: skip the whole block
		},
	}
	for i, off := range zeroWordOffsets {
		// On a nonzero word, jump to the trailing EPERM: past the remaining
		// checks (2 insns each) and the ALLOW (1 insn).
		jf := uint8(2*(len(zeroWordOffsets)-i-1) + 1)
		block = append(block,
			SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: off},
			SockFilter{
				Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
				K:    0,
				Jt:   0,  // zero so far: keep checking
				Jf:   jf, // nonzero: deny
			},
		)
	}
	return append(block, allow, eperm)
}

// buildIoctlArgFilter emits the two-stage rule for ioctl: on a syscall-number
// match, load the request argument and compare it against
// allowedIoctlRequests; a request outside the allowlist returns
// ERRNO(EPERM) — the same action as a blocked syscall number. The classic
// BPF jump offsets are relative: the initial JEQ's Jf skips the whole
// argument block (1 LD + 2 per request + 1 EPERM).
//
// ioctl stays argument-filtered even under the denylist: it multiplexes the
// entire kernel driver surface onto one number, and the jail shares the
// host NETWORK namespace (interface setters like SIOCSIFFLAGS would
// otherwise be reachable).
func buildIoctlArgFilter(nr uint32) []SockFilter {
	eperm := SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA),
	}
	block := []SockFilter{
		{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			K:    nr,
			Jt:   0,                                      // match: fall through to the argument check
			Jf:   uint8(2 + 2*len(allowedIoctlRequests)), // mismatch: skip the block
		},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompArg1LowOffset},
	}
	for _, req := range allowedIoctlRequests {
		block = append(block,
			SockFilter{
				Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
				K:    req,
				Jt:   0, // match: execute the ALLOW instruction directly below
				Jf:   1, // mismatch: skip ALLOW, check the next request
			},
			SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		)
	}
	return append(block, eperm)
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
