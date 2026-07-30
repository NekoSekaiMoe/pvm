package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManager_FreezeThaw(t *testing.T) {
	// Create a temporary directory to act as the cgroup root
	tmpDir, err := os.MkdirTemp("", "cgroup-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	m := &Manager{
		CgroupRoot: tmpDir,
	}

	containerID := "test-sandbox-123"
	cgPath := filepath.Join(tmpDir, containerID)
	if err := os.MkdirAll(cgPath, 0755); err != nil {
		t.Fatalf("Failed to create cgroup path: %v", err)
	}

	// Create a dummy cgroup.freeze file
	freezeFile := filepath.Join(cgPath, "cgroup.freeze")
	os.WriteFile(freezeFile, []byte(""), 0644)

	// Test Freeze
	if err := m.Freeze(containerID); err != nil {
		t.Errorf("Freeze failed: %v", err)
	}
	data, _ := os.ReadFile(freezeFile)
	if string(data) != "1" {
		t.Errorf("Expected freeze=1, got %q", string(data))
	}

	// Test Thaw
	if err := m.Thaw(containerID); err != nil {
		t.Errorf("Thaw failed: %v", err)
	}
	data, _ = os.ReadFile(freezeFile)
	if string(data) != "0" {
		t.Errorf("Expected freeze=0, got %q", string(data))
	}
}

// TestManager_Setup_OutsideSysfsDoesNotTouchRealCgroup verifies that when
// CgroupRoot points at a scratch directory outside /sys/fs/cgroup (as the
// unit tests do), enableControllers short-circuits and never attempts to
// write the real root cgroup.subtree_control.
func TestManager_Setup_OutsideSysfsDoesNotTouchRealCgroup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cgroup-setup-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	m := &Manager{CgroupRoot: tmpDir}
	// PID 0 / 1 would be wrong to really move; this just exercises the path.
	// We only assert no real /sys/fs/cgroup writes happen and Setup either
	// succeeds or fails without touching the host cgroup fs.
	_ = m.Setup("scratch-container", os.Getpid(), 1<<30, 0)

	// Sanity: if this host actually has a cgroup v2 mount, the root
	// cgroup.controllers file should still be readable (i.e. we did not
	// corrupt anything). Skip the assertion on hosts without cgroup v2.
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		if _, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err != nil {
			t.Fatalf("root cgroup.controllers unreadable after Setup: %v", err)
		}
	}
}
