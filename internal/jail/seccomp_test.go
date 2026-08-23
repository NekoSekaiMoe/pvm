package jail

import (
	"os"
	"os/exec"
	"testing"
)

// TestSeccompHelperProcess tests applying the BPF filter inside an isolated subprocess.
func TestSeccompHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SECCOMP_HELPER") != "1" {
		return
	}
	if err := ApplyHostSeccompFilter(); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestSeccomp_AllowedSyscallsIntegrity(t *testing.T) {
	// Must allow ptrace for UML SKAS execution
	if !IsSyscallAllowed("ptrace") {
		t.Errorf("expected 'ptrace' to be allowed for UML")
	}
	// Must allow mmap and mprotect for UML page handling
	if !IsSyscallAllowed("mmap") || !IsSyscallAllowed("mprotect") {
		t.Errorf("expected 'mmap' and 'mprotect' to be allowed for UML")
	}
	// Must allow signal handling
	if !IsSyscallAllowed("rt_sigaction") || !IsSyscallAllowed("rt_sigprocmask") {
		t.Errorf("expected signal syscalls to be allowed for UML")
	}
}

func TestSeccomp_BlockedDangerousSyscalls(t *testing.T) {
	dangerous := []string{
		"bpf",
		"io_uring_setup",
		"kexec_load",
		"sys_chroot",
		"mount",
		"unshare",
		"setns",
	}

	for _, d := range dangerous {
		if !IsSyscallDangerous(d) {
			t.Errorf("expected syscall %s to be flagged as dangerous", d)
		}
		if IsSyscallAllowed(d) {
			t.Errorf("dangerous syscall %s MUST NOT be in UML allowed set", d)
		}
	}
}

func TestSeccomp_FilterGeneration(t *testing.T) {
	filter := BuildUMLSeccompFilter()
	if len(filter) == 0 {
		t.Fatalf("expected non-empty BPF filter")
	}
}

func TestSeccomp_ApplyInSubprocess(t *testing.T) {
	caps := DetectHostCapabilities()
	if !caps.HasSeccomp {
		t.Skip("skipping seccomp apply test: seccomp not supported on host")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_SECCOMP_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Seccomp helper process failed: %v, output: %s", err, string(out))
	}
}
