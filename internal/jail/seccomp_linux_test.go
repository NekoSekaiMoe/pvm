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
// BuildUMLSeccompFilter against a synthetic seccomp_data record
// {nr @ offset 0, arch @ offset 4, args[1] low word @ offset 24} and
// returns the SECCOMP_RET_* action.
func simulateSeccompFilter(t *testing.T, filter []SockFilter, nr, arch, arg1Low uint32) uint32 {
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
			switch ins.K {
			case 0:
				a = nr
			case 4:
				a = arch
			case seccompArg1LowOffset:
				a = arg1Low
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

// TestSeccomp_FilterBranchSemantics verifies the JEQ jump logic of the
// generated filter: matched (allowed) syscalls fall through to
// SECCOMP_RET_ALLOW, unmatched ones skip it and end at the default EPERM.
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
		{"allowed write", uint32(unix.SYS_WRITE), unix.SECCOMP_RET_ALLOW},
		{"allowed getpid", uint32(unix.SYS_GETPID), unix.SECCOMP_RET_ALLOW},
		{"allowed ptrace", uint32(unix.SYS_PTRACE), unix.SECCOMP_RET_ALLOW},
		// The jail helper's final handoff to the workload: without this
		// entry the helper dies with EPERM at exec time.
		{"allowed execve", uint32(unix.SYS_EXECVE), unix.SECCOMP_RET_ALLOW},
		// Loader/libc startup regressions (the filter is installed before
		// execve, so it constrains ld.so too):
		//  - fstat: ld.so stats every shared object it loads; without it a
		//    dynamic workload dies with "cannot stat shared object:
		//    Operation not permitted".
		//  - getrlimit/prlimit64: UML main() -> set_stklim() exits(1) with
		//    "getrlimit: Operation not permitted" when denied.
		//  - wait4: waitpid() backing for guest-thread reaping.
		{"allowed fstat", uint32(unix.SYS_FSTAT), unix.SECCOMP_RET_ALLOW},
		{"allowed getrlimit", uint32(unix.SYS_GETRLIMIT), unix.SECCOMP_RET_ALLOW},
		{"allowed prlimit64", uint32(unix.SYS_PRLIMIT64), unix.SECCOMP_RET_ALLOW},
		{"allowed wait4", uint32(unix.SYS_WAIT4), unix.SECCOMP_RET_ALLOW},
		{"blocked unshare", uint32(unix.SYS_UNSHARE), errnoEPERM},
		{"blocked mount", uint32(unix.SYS_MOUNT), errnoEPERM},
		{"blocked bpf", uint32(unix.SYS_BPF), errnoEPERM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := simulateSeccompFilter(t, filter, tc.nr, arch, 0); got != tc.want {
				t.Errorf("syscall nr=%d: got action %#x, want %#x", tc.nr, got, tc.want)
			}
		})
	}

	t.Run("wrong arch denied", func(t *testing.T) {
		badArch := uint32(unix.AUDIT_ARCH_X86_64)
		if arch == badArch {
			badArch = unix.AUDIT_ARCH_AARCH64
		}
		if got := simulateSeccompFilter(t, filter, uint32(unix.SYS_WRITE), badArch, 0); got != errnoEPERM {
			t.Errorf("wrong arch: got action %#x, want %#x", got, errnoEPERM)
		}
	})
}

// TestSeccomp_AllowedSyscallsResolvable pins the contract that every name
// in UMLAllowedSyscalls resolves to a real syscall number via
// getSyscallNumber. BuildUMLSeccompFilter silently skips unresolvable
// names, so a missing table entry would quietly drop the syscall from the
// installed filter — this is exactly how execve once fell to the default
// EPERM and killed the jail helper's workload handoff.
func TestSeccomp_AllowedSyscallsResolvable(t *testing.T) {
	for _, name := range UMLAllowedSyscalls {
		t.Run(name, func(t *testing.T) {
			nr, ok := getSyscallNumber(name)
			if !ok || nr < 0 {
				t.Errorf("allowed syscall %q has no syscall-table entry; it will be silently denied (EPERM) by the installed filter", name)
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
			if got := simulateSeccompFilter(t, filter, uint32(unix.SYS_IOCTL), arch, req); got != unix.SECCOMP_RET_ALLOW {
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
			if got := simulateSeccompFilter(t, filter, uint32(unix.SYS_IOCTL), arch, tc.req); got != errnoEPERM {
				t.Errorf("ioctl request %#x: got action %#x, want %#x", tc.req, got, errnoEPERM)
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
