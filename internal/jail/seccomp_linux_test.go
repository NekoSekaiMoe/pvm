//go:build linux

package jail

import (
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// simulateSeccompFilter interprets the classic BPF filter produced by
// BuildUMLSeccompFilter against a synthetic seccomp_data record
// {nr @ offset 0, arch @ offset 4} and returns the SECCOMP_RET_* action.
func simulateSeccompFilter(t *testing.T, filter []SockFilter, nr, arch uint32) uint32 {
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
		{"blocked unshare", uint32(unix.SYS_UNSHARE), errnoEPERM},
		{"blocked mount", uint32(unix.SYS_MOUNT), errnoEPERM},
		{"blocked bpf", uint32(unix.SYS_BPF), errnoEPERM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := simulateSeccompFilter(t, filter, tc.nr, arch); got != tc.want {
				t.Errorf("syscall nr=%d: got action %#x, want %#x", tc.nr, got, tc.want)
			}
		})
	}

	t.Run("wrong arch denied", func(t *testing.T) {
		badArch := uint32(unix.AUDIT_ARCH_X86_64)
		if arch == badArch {
			badArch = unix.AUDIT_ARCH_AARCH64
		}
		if got := simulateSeccompFilter(t, filter, uint32(unix.SYS_WRITE), badArch); got != errnoEPERM {
			t.Errorf("wrong arch: got action %#x, want %#x", got, errnoEPERM)
		}
	})
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
