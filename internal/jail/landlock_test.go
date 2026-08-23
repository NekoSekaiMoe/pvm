package jail

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestLandlockHelperProcess is invoked as a subprocess so that Landlock lockdown
// is applied ONLY to the child process and does NOT contaminate the parent test runner process.
func TestLandlockHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_LANDLOCK_HELPER") != "1" {
		return
	}
	allowed := os.Getenv("LANDLOCK_ALLOWED_DIR")
	if err := ApplyLandlockLockdown([]string{allowed}); err != nil {
		os.Exit(2)
	}
	// Try writing to allowed path
	testFile := filepath.Join(allowed, "test.txt")
	if err := os.WriteFile(testFile, []byte("ok"), 0644); err != nil {
		os.Exit(3)
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

	cmd := exec.Command(os.Args[0], "-test.run=TestLandlockHelperProcess")
	cmd.Env = append(os.Environ(),
		"GO_WANT_LANDLOCK_HELPER=1",
		"LANDLOCK_ALLOWED_DIR="+p1,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Landlock helper process failed: %v, output: %s", err, string(out))
	}
}
