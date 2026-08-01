package cow

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateOverlay_QemuImgMissing(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err == nil {
		t.Skip("qemu-img installed; cannot exercise missing-binary path")
	}
	out := filepath.Join(t.TempDir(), "overlay.qcow2")
	err := CreateOverlay("/nonexistent/base.img", out, FormatRaw)
	if err == nil {
		t.Fatal("expected error when qemu-img missing")
	}
}

func TestValidatePath_RejectsComma(t *testing.T) {
	if err := validatePath("/safe/path.img"); err != nil {
		t.Errorf("safe path rejected: %v", err)
	}
	if err := validatePath("/bad/file,opt=evil"); err == nil {
		t.Error("comma path should be rejected (option injection)")
	}
	if err := validatePath(""); err == nil {
		t.Error("empty path should be rejected")
	}
}

// TestCreateOverlay_RealQemu exercises the happy path when qemu-img exists.
// It creates a tiny raw base, makes an overlay, and verifies the overlay file
// is a real qcow2 (magic header "QFI\xfb").
func TestCreateOverlay_RealQemu(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	// 1MB raw base
	if err := os.WriteFile(base, make([]byte, 1<<20), 0644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(base, overlay, FormatRaw); err != nil {
		t.Fatalf("create: %v", err)
	}
	hdr := make([]byte, 4)
	f, err := os.Open(overlay)
	if err != nil {
		t.Fatalf("open overlay: %v", err)
	}
	defer f.Close()
	if _, err := f.Read(hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if string(hdr) != "QFI\xfb" {
		t.Errorf("overlay is not qcow2 (magic=%q)", string(hdr))
	}
}

func TestCreateOverlay_IdempotentRecreate(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	os.WriteFile(base, make([]byte, 1<<20), 0644)
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(base, overlay, FormatRaw); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// taint the overlay
	if err := os.WriteFile(overlay, []byte("stale"), 0644); err == nil {
		_ = err
	}
	// second create should replace, not append/reuse the tainted file
	if err := CreateOverlay(base, overlay, FormatRaw); err != nil {
		t.Fatalf("second create: %v", err)
	}
	data, _ := os.ReadFile(overlay)
	if strings.HasPrefix(string(data), "stale") {
		t.Error("overlay was not replaced on recreate (stale data leaked)")
	}
}
