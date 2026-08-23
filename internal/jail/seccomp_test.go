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
	cases := []struct {
		name   string
		reason string
	}{
		{"ptrace", "UML SKAS execution"},
		{"mmap", "UML page handling"},
		{"mprotect", "UML page handling"},
		{"rt_sigaction", "signal handling"},
		{"rt_sigprocmask", "signal handling"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !IsSyscallAllowed(tc.name) {
				t.Errorf("expected %q to be allowed for UML (%s)", tc.name, tc.reason)
			}
		})
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
		t.Run(d, func(t *testing.T) {
			if !IsSyscallDangerous(d) {
				t.Errorf("expected syscall %s to be flagged as dangerous", d)
			}
			if IsSyscallAllowed(d) {
				t.Errorf("dangerous syscall %s MUST NOT be in UML allowed set", d)
			}
		})
	}
}

func TestSeccomp_FilterGeneration(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"non-empty filter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter := BuildUMLSeccompFilter()
			if len(filter) == 0 {
				t.Fatalf("expected non-empty BPF filter")
			}
		})
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
