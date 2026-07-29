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
