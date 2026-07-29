package cow

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateOverlay_QemuImgMissing(t *testing.T) {
	// If qemu-img is not on PATH, CreateOverlay must return a non-nil error
	// mentioning qemu-img; this guards against silently treating CoW creation
	// as best-effort.
	if _, err := exec.LookPath("qemu-img"); err == nil {
		t.Skip("qemu-img is installed; the missing-binary path cannot be exercised here")
	}

	out := filepath.Join(t.TempDir(), "overlay.qcow2")
	err := CreateOverlay("/nonexistent/base.img", out, "raw")
	if err == nil {
		t.Fatalf("expected error when qemu-img is missing, got nil")
	}
	if !strings.Contains(err.Error(), "qemu-img") && !strings.Contains(err.Error(), "failed to create qcow2 overlay") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCreateOverlay_NonExistentBacking(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed; skipping backing-file validation test")
	}
	out := filepath.Join(t.TempDir(), "overlay.qcow2")
	err := CreateOverlay("/definitely/does/not/exist/base.img", out, "raw")
	if err == nil {
		// qemu-img may succeed creating an overlay whose backing file is later
		// resolved lazily; ensure the produced file at least exists.
		if _, statErr := os.Stat(out); statErr != nil {
			t.Fatalf("overlay reported success but file missing: %v", statErr)
		}
		return
	}
	// Error path: backing file invalid -> qemu-img should refuse.
	if !strings.Contains(err.Error(), "qcow2 overlay") {
		t.Errorf("unexpected error: %v", err)
	}
}
