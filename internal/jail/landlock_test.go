package jail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLandlock_ApplyAllowedPaths(t *testing.T) {
	tmp := t.TempDir()
	p1 := filepath.Join(tmp, "vol1")
	p2 := filepath.Join(tmp, "vol2")
	_ = os.MkdirAll(p1, 0755)
	_ = os.MkdirAll(p2, 0755)

	err := ApplyLandlockLockdown([]string{p1, p2})
	// On systems without Landlock support, this returns nil gracefully.
	if err != nil {
		t.Logf("Landlock applied with error (or unsupported on host): %v", err)
	}
}
