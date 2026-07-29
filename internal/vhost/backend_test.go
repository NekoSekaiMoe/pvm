package vhost

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"uml-container/internal/state"
)

func TestStartStorageDaemon_RejectsCommaInPath(t *testing.T) {
	// imagePath is interpolated directly into qemu-storage-daemon args; a comma
	// would inject a new option. The code must reject it before exec.
	root := t.TempDir()
	orig := state.RootDir
	state.RootDir = root
	defer func() { state.RootDir = orig }()

	_, _, err := StartStorageDaemon("c-comma", "/tmp/a,b.img")
	if err == nil {
		t.Fatal("expected error for comma in imagePath, got nil")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Errorf("error should mention comma, got: %v", err)
	}
}

func TestStartStorageDaemon_DaemonMissing(t *testing.T) {
	if _, err := exec.LookPath("qemu-storage-daemon"); err != nil {
		t.Skip("qemu-storage-daemon not on PATH")
	}
	root := t.TempDir()
	orig := state.RootDir
	state.RootDir = root
	defer func() { state.RootDir = orig }()

	_, _, err := StartStorageDaemon("c-nodaemon", "/tmp/nope.img")
	if err == nil {
		t.Fatal("expected error when qemu-storage-daemon fails to start, got nil")
	}
}

func TestStartStorageDaemon_PrepareStateDir(t *testing.T) {
	// Even when the daemon can't start, the container dir must be created
	// (state.ContainerDir + MkdirAll). We assert that side effect with a bad
	// image path so the daemon either refuses to start or times out quickly.
	root := t.TempDir()
	orig := state.RootDir
	state.RootDir = root
	defer func() { state.RootDir = orig }()

	_, _, _ = StartStorageDaemon("c-prep", "/tmp/nope.img")
	dir := filepath.Join(root, "c-prep")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("container dir %s was not prepared: %v", dir, err)
	}
}

// exists was a placeholder; tests use exec.LookPath directly.
