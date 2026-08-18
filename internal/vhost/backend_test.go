package vhost

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"uml-container/internal/state"
)

func useTempState(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	orig := state.RootDir
	state.RootDir = root
	t.Cleanup(func() { state.RootDir = orig })
}

// TestStartBlk_GoBackend: the default (pure-Go) backend serves a socket
// immediately and needs no external daemon.
func TestStartBlk_GoBackend(t *testing.T) {
	useTempState(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "base.img")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0644); err != nil {
		t.Fatalf("write image: %v", err)
	}
	t.Setenv("PVM_VHOST_BACKEND", "")
	sock, closer, err := StartBlk("c-go", img)
	if err != nil {
		t.Fatalf("StartBlk: %v", err)
	}
	defer closer.Close()
	defer os.Remove(sock)
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket not published: %v", err)
	}
}

// TestStartBlk_GoBackendBadImage: a missing image fails before serving.
func TestStartBlk_GoBackendBadImage(t *testing.T) {
	useTempState(t)
	t.Setenv("PVM_VHOST_BACKEND", "")
	// Guaranteed-nonexistent image path under the test's temp dir.
	_, _, err := StartBlk("c-go-bad", filepath.Join(t.TempDir(), "missing.img"))
	if err == nil {
		t.Fatal("expected error for missing image")
	}
}

// TestStartBlk_QemuRejectsCommaInPath: imagePath is interpolated into
// qemu-storage-daemon args; a comma would inject a new option.
func TestStartBlk_QemuRejectsCommaInPath(t *testing.T) {
	useTempState(t)
	t.Setenv("PVM_VHOST_BACKEND", "qemu")
	_, _, err := StartBlk("c-comma", "/tmp/a,b.img")
	if err == nil {
		t.Fatal("expected error for comma in imagePath, got nil")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Errorf("error should mention comma, got: %v", err)
	}
}

// TestStartBlk_QemuDaemonMissing exercises the qemu fallback's failure path.
func TestStartBlk_QemuDaemonMissing(t *testing.T) {
	if _, err := exec.LookPath("qemu-storage-daemon"); err != nil {
		t.Skip("qemu-storage-daemon not on PATH")
	}
	useTempState(t)
	t.Setenv("PVM_VHOST_BACKEND", "qemu")
	_, _, err := StartBlk("c-nodaemon", "/tmp/nope.img")
	if err == nil {
		t.Fatal("expected error when qemu-storage-daemon fails to start, got nil")
	}
}

// TestStartBlk_PrepareStateDir: even when the backend can't start, the
// container dir must be created (prepareSocket before opening the image).
func TestStartBlk_PrepareStateDir(t *testing.T) {
	root := t.TempDir()
	orig := state.RootDir
	state.RootDir = root
	defer func() { state.RootDir = orig }()

	_, _, _ = StartBlk("c-prep", "/tmp/nope.img")
	dir := filepath.Join(root, "c-prep")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("container dir %s was not prepared: %v", dir, err)
	}
}
