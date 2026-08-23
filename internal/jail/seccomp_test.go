package jail

import (
	"testing"
)

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
