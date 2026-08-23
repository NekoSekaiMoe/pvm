//go:build linux

package jail

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// simulateSeccompFilter interprets the classic BPF filter produced by
// BuildUMLSeccompFilter against a synthetic seccomp_data record {nr @
// offset 0, arch @ 4, args @ 16 (six 64-bit words, little-endian)} and
// returns the SECCOMP_RET_* action. Argument-filtered rules (ioctl,
// prlimit64) load individual 32-bit words of the 64-bit arguments; the
// simulator reconstructs them from args so tests can exercise full 64-bit
// values (e.g. a pointer with only its high word set).
func simulateSeccompFilter(t *testing.T, filter []SockFilter, nr, arch uint32, args [6]uint64) uint32 {
	t.Helper()
	var a uint32
	pc := 0
	for {
		if pc < 0 || pc >= len(filter) {
			t.Fatalf("program counter out of range: %d (filter len %d)", pc, len(filter))
		}
		ins := filter[pc]
		switch ins.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch {
			case ins.K == 0:
				a = nr
			case ins.K == 4:
				a = arch
			case ins.K >= 16 && ins.K <= 56 && (ins.K-16)%4 == 0:
				word := (ins.K - 16) / 4 // 0..11: low/high words of args[0..5]
				if word%2 == 0 {
					a = uint32(args[word/2]) // low 32 bits
				} else {
					a = uint32(args[word/2] >> 32) // high 32 bits
				}
			default:
				t.Fatalf("unexpected BPF_ABS offset %d", ins.K)
			}
			pc++
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == ins.K {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return ins.K
		default:
			t.Fatalf("unsupported BPF opcode %#x at pc=%d", ins.Code, pc)
		}
	}
}

func hostAuditArch() uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	}
	return 0
}

// TestSeccomp_FilterBranchSemantics verifies the DENYLIST jump logic of
// the generated filter: dangerous syscalls match a JEQ and reach
// SECCOMP_RET_ERRNO(EPERM); everything else — including the long tail of
// loader/libc/UML syscalls that the old allowlist kept missing (fstat,
// getrlimit, timer_create, restart_syscall, set_robust_list, ...) — falls
// through to the default SECCOMP_RET_ALLOW.
func TestSeccomp_FilterBranchSemantics(t *testing.T) {
	arch := hostAuditArch()
	if arch == 0 {
		t.Skip("unsupported architecture for audit arch check")
	}
	filter := BuildUMLSeccompFilter()
	errnoEPERM := uint32(unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA))

	cases := []struct {
		name string
		nr   uint32
		want uint32
	}{
		// Default-allowed: the historical allowlist gaps that each killed a
		// boot (see the policy comment in seccomp_linux.go). Under the
		// denylist these pass without any per-syscall rule.
		{"allowed write", uint32(unix.SYS_WRITE), unix.SECCOMP_RET_ALLOW},
		{"allowed getpid", uint32(unix.SYS_GETPID), unix.SECCOMP_RET_ALLOW},
		{"allowed ptrace", uint32(unix.SYS_PTRACE), unix.SECCOMP_RET_ALLOW},
		{"allowed execve", uint32(unix.SYS_EXECVE), unix.SECCOMP_RET_ALLOW},
		{"allowed fstat (ld.so stat of shared objects)", uint32(unix.SYS_FSTAT), unix.SECCOMP_RET_ALLOW},
		{"allowed getrlimit (UML set_stklim)", uint32(unix.SYS_GETRLIMIT), unix.SECCOMP_RET_ALLOW},
		{"allowed wait4 (guest-thread reaping)", uint32(unix.SYS_WAIT4), unix.SECCOMP_RET_ALLOW},
		{"allowed timer_create (guest tick)", uint32(unix.SYS_TIMER_CREATE), unix.SECCOMP_RET_ALLOW},
		{"allowed timer_settime", uint32(unix.SYS_TIMER_SETTIME), unix.SECCOMP_RET_ALLOW},
		{"allowed restart_syscall (signal-interrupted resume)", uint32(unix.SYS_RESTART_SYSCALL), unix.SECCOMP_RET_ALLOW},
		{"allowed set_robust_list (glibc init)", uint32(unix.SYS_SET_ROBUST_LIST), unix.SECCOMP_RET_ALLOW},
		{"allowed set_tid_address", uint32(unix.SYS_SET_TID_ADDRESS), unix.SECCOMP_RET_ALLOW},
		{"allowed rseq", uint32(unix.SYS_RSEQ), unix.SECCOMP_RET_ALLOW},
		// Dangerous denylist entries must hit EPERM.
		{"blocked unshare", uint32(unix.SYS_UNSHARE), errnoEPERM},
		{"blocked mount", uint32(unix.SYS_MOUNT), errnoEPERM},
		{"blocked bpf", uint32(unix.SYS_BPF), errnoEPERM},
		{"blocked setns", uint32(unix.SYS_SETNS), errnoEPERM},
		{"blocked settimeofday (host clock)", uint32(unix.SYS_SETTIMEOFDAY), errnoEPERM},
		{"blocked clock_settime", uint32(unix.SYS_CLOCK_SETTIME), errnoEPERM},
		{"blocked process_vm_writev (host memory)", uint32(unix.SYS_PROCESS_VM_WRITEV), errnoEPERM},
		{"blocked userfaultfd", uint32(unix.SYS_USERFAULTFD), errnoEPERM},
		{"blocked swapon", uint32(unix.SYS_SWAPON), errnoEPERM},
		{"blocked syslog", uint32(unix.SYS_SYSLOG), errnoEPERM},
		{"blocked move_mount (new mount API)", uint32(unix.SYS_MOVE_MOUNT), errnoEPERM},
		{"blocked open_tree", uint32(unix.SYS_OPEN_TREE), errnoEPERM},
		{"blocked open_by_handle_at (Landlock bypass)", uint32(unix.SYS_OPEN_BY_HANDLE_AT), errnoEPERM},
		{"blocked name_to_handle_at", uint32(unix.SYS_NAME_TO_HANDLE_AT), errnoEPERM},
		{"blocked pidfd_send_signal (host PIDs)", uint32(unix.SYS_PIDFD_SEND_SIGNAL), errnoEPERM},
		{"blocked process_mrelease", uint32(unix.SYS_PROCESS_MRELEASE), errnoEPERM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := simulateSeccompFilter(t, filter, tc.nr, arch, [6]uint64{}); got != tc.want {
				t.Errorf("syscall nr=%d: got action %#x, want %#x", tc.nr, got, tc.want)
			}
		})
	}

	t.Run("wrong arch denied", func(t *testing.T) {
		badArch := uint32(unix.AUDIT_ARCH_X86_64)
		if arch == badArch {
			badArch = unix.AUDIT_ARCH_AARCH64
		}
		if got := simulateSeccompFilter(t, filter, uint32(unix.SYS_WRITE), badArch, [6]uint64{}); got != errnoEPERM {
			t.Errorf("wrong arch: got action %#x, want %#x", got, errnoEPERM)
		}
	})
}

// TestSeccomp_BlockedSyscallsResolvable pins the contract that every name
// the filter consults — the denylist (BlockedDangerousSyscalls + per-arch
// extras) and the argument-filtered syscalls — resolves to a real syscall
// number via getSyscallNumber. Under a DENYLIST an unresolvable name is a
// fail-OPEN gap: the syscall silently stays allowed. This is the mirror
// image of the old allowlist resolvability test (there a missing entry
// silently denied a needed syscall).
func TestSeccomp_BlockedSyscallsResolvable(t *testing.T) {
	for _, name := range append(append([]string{}, blockedSyscallsEffective...), "ioctl", "prlimit64") {
		t.Run(name, func(t *testing.T) {
			nr, ok := getSyscallNumber(name)
			if !ok || nr < 0 {
				t.Errorf("blocked/arg-filtered syscall %q has no syscall-table entry; it will be silently ALLOWED by the installed filter", name)
			}
		})
	}
}

// TestSeccomp_IoctlArgFiltering verifies the second-stage argument check on
// ioctl: every allowlisted request number reaches SECCOMP_RET_ALLOW while
// any other request — including harmless-looking setters — falls to
// ERRNO(EPERM), the same action as a blocked syscall number.
func TestSeccomp_IoctlArgFiltering(t *testing.T) {
	arch := hostAuditArch()
	if arch == 0 {
		t.Skip("unsupported architecture for audit arch check")
	}
	filter := BuildUMLSeccompFilter()
	errnoEPERM := uint32(unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA))

	if len(allowedIoctlRequests) == 0 {
		t.Fatal("allowedIoctlRequests must not be empty (ioctl would be fully blocked)")
	}
	for _, req := range allowedIoctlRequests {
		t.Run(fmt.Sprintf("allowed request %#x", req), func(t *testing.T) {
			if got := simulateSeccompFilter(t, filter, uint32(unix.SYS_IOCTL), arch, [6]uint64{1: uint64(req)}); got != unix.SECCOMP_RET_ALLOW {
				t.Errorf("ioctl request %#x: got action %#x, want ALLOW", req, got)
			}
		})
	}

	denied := []struct {
		name string
		req  uint32
	}{
		{"interface setter SIOCSIFFLAGS", 0x8914},
		{"TAP sndbuf setter TUNSETSNDBUF", 0x400454D4},
		{"unlisted device command", 0xDEAD},
		{"zero", 0},
	}
	for _, tc := range denied {
		t.Run("denied "+tc.name, func(t *testing.T) {
			if got := simulateSeccompFilter(t, filter, uint32(unix.SYS_IOCTL), arch, [6]uint64{1: uint64(tc.req)}); got != errnoEPERM {
				t.Errorf("ioctl request %#x: got action %#x, want %#x", tc.req, got, errnoEPERM)
			}
		})
	}
}

// TestSeccomp_Prlimit64ArgFiltering verifies the second-stage argument
// check on prlimit64: only read-only self-queries (pid == 0 &&
// new_limit == NULL) reach SECCOMP_RET_ALLOW. Both arguments are compared
// as complete 64-bit values, so a pid or pointer with only its high word
// set must still be denied. getrlimit stays unrestricted (it can only ever
// read the calling process's limits).
func TestSeccomp_Prlimit64ArgFiltering(t *testing.T) {
	arch := hostAuditArch()
	if arch == 0 {
		t.Skip("unsupported architecture for audit arch check")
	}
	filter := BuildUMLSeccompFilter()
	errnoEPERM := uint32(unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA))

	cases := []struct {
		name string
		args [6]uint64 // [0]=pid [1]=resource [2]=new_limit [3]=old_limit
		want uint32
	}{
		{"self read (pid=0, new=NULL)", [6]uint64{}, unix.SECCOMP_RET_ALLOW},
		{"self read with old_limit output set", [6]uint64{3: 0x7fff00008000}, unix.SECCOMP_RET_ALLOW},
		{"self read, any resource selector", [6]uint64{1: unix.RLIMIT_NOFILE}, unix.SECCOMP_RET_ALLOW},
		{"deny other pid", [6]uint64{0: 1234}, errnoEPERM},
		{"deny pid with high word set (64-bit compare)", [6]uint64{0: 1 << 32}, errnoEPERM},
		{"deny non-NULL new_limit (limit raise)", [6]uint64{2: 0x7fff00008000}, errnoEPERM},
		{"deny new_limit high word only (64-bit compare)", [6]uint64{2: 1 << 32}, errnoEPERM},
		{"deny pid=1 even with new=NULL", [6]uint64{0: 1}, errnoEPERM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := simulateSeccompFilter(t, filter, uint32(unix.SYS_PRLIMIT64), arch, tc.args); got != tc.want {
				t.Errorf("prlimit64 args=%v: got action %#x, want %#x", tc.args, got, tc.want)
			}
		})
	}
}

// TestSeccompSyscallHelperProcess applies the real filter in a subprocess and
// exercises both branches with actual syscalls: allowed ones (getpid, write)
// must succeed, a blocked one (unshare) must fail with EPERM.
func TestSeccompSyscallHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SECCOMP_SYSCALL_HELPER") != "1" {
		return
	}
	if err := ApplyHostSeccompFilter(); err != nil {
		os.Exit(2)
	}
	// Allowed branch: getpid must succeed.
	if unix.Getpid() <= 0 {
		os.Exit(3)
	}
	// Allowed branch: write must succeed.
	if _, err := unix.Write(1, []byte("seccomp syscall helper ok\n")); err != nil {
		os.Exit(4)
	}
	// Denylist default: a benign syscall that was NEVER in the old
	// allowlist must now succeed (getpriority was not allowlisted).
	if _, err := unix.Getpriority(unix.PRIO_PROCESS, 0); err != nil {
		os.Exit(10)
	}
	// Blocked branch: unshare must fail with EPERM.
	if _, _, errno := unix.Syscall(unix.SYS_UNSHARE, 0, 0, 0); errno != unix.EPERM {
		os.Exit(5)
	}
	// ioctl argument filter: an allowlisted request must reach the kernel
	// (fd 1 is a pipe here, so TCGETS fails with ENOTTY — anything but
	// EPERM proves the filter let it through), while an unlisted request
	// must be blocked with EPERM.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, 1, ioctlTCGETS, 0); errno == unix.EPERM {
		os.Exit(6)
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, 1, 0xDEAD, 0); errno != unix.EPERM {
		os.Exit(7)
	}
	// prlimit64 argument filter: a read-only self query (pid=0,
	// new_limit=NULL) must reach the kernel and succeed, while any limit
	// SET attempt (non-NULL new_limit) must be blocked with EPERM — even
	// when re-setting the identical values.
	var rl unix.Rlimit
	if err := unix.Prlimit(0, unix.RLIMIT_NOFILE, nil, &rl); err != nil {
		os.Exit(8)
	}
	if err := unix.Prlimit(0, unix.RLIMIT_NOFILE, &rl, nil); err != unix.EPERM {
		os.Exit(9)
	}
	os.Exit(0)
}

func TestSeccomp_FilterEnforcement(t *testing.T) {
	caps := DetectHostCapabilities()
	if !caps.HasSeccomp {
		t.Skip("skipping seccomp enforcement test: seccomp not supported on host")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSeccompSyscallHelperProcess$")
	cmd.Env = append(os.Environ(), "GO_WANT_SECCOMP_SYSCALL_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Seccomp enforcement helper process failed: %v, output: %s", err, string(out))
	}
}
