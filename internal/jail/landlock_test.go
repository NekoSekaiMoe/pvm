package jail

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// TestLandlockHelperProcess is invoked as a subprocess so that Landlock lockdown
// is applied ONLY to the child process and does NOT contaminate the parent test runner process.
func TestLandlockHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_LANDLOCK_HELPER") != "1" {
		return
	}
	allowed := os.Getenv("LANDLOCK_ALLOWED_DIR")
	denied := os.Getenv("LANDLOCK_DENIED_DIR")
	if err := ApplyLandlockLockdown([]string{allowed}); err != nil {
		os.Exit(2)
	}
	// Writing inside the allowed directory must succeed.
	testFile := filepath.Join(allowed, "test.txt")
	if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
		os.Exit(3)
	}
	// Writing inside the denied directory must fail with EACCES.
	if denied != "" {
		deniedFile := filepath.Join(denied, "test.txt")
		err := os.WriteFile(deniedFile, []byte("nope"), 0644)
		if err == nil {
			os.Exit(4) // write unexpectedly succeeded
		}
		if !errors.Is(err, syscall.EACCES) {
			os.Exit(5) // write failed, but not with EACCES
		}
	}
	os.Exit(0)
}

func TestLandlock_ApplyAllowedPaths(t *testing.T) {
	caps := DetectHostCapabilities()
	if !caps.HasLandlock {
		t.Skip("skipping Landlock test: Landlock LSM not supported or enabled on host")
	}

	tmp := t.TempDir()
	p1 := filepath.Join(tmp, "vol1")
	if err := os.MkdirAll(p1, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	denied := filepath.Join(tmp, "denied")
	if err := os.MkdirAll(denied, 0755); err != nil {
		t.Fatalf("mkdir denied: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockHelperProcess$")
	cmd.Env = append(os.Environ(),
		"GO_WANT_LANDLOCK_HELPER=1",
		"LANDLOCK_ALLOWED_DIR="+p1,
		"LANDLOCK_DENIED_DIR="+denied,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Landlock helper process failed: %v, output: %s", err, string(out))
	}
}
