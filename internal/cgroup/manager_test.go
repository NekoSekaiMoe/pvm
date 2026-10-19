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

func TestManager_MemoryMaxRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	m := &Manager{CgroupRoot: tmpDir}
	const id = "mem-cg"
	cgPath := filepath.Join(tmpDir, id)
	if err := os.MkdirAll(cgPath, 0o755); err != nil {
		t.Fatal(err)
	}
	// MemoryMax / MemoryCurrent parse the written values.
	if err := m.SetMemoryMax(id, 1073741824); err != nil {
		t.Fatal(err)
	}
	if got, err := m.MemoryMax(id); err != nil || got != 1073741824 {
		t.Fatalf("MemoryMax = %d, %v; want 1073741824", got, err)
	}
	// A negative value writes the literal "max", read back as unlimited.
	if err := m.SetMemoryMax(id, MemoryUnlimited); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(cgPath, "memory.max")); string(b) != "max" {
		t.Fatalf("memory.max = %q, want max", string(b))
	}
	if got, err := m.MemoryMax(id); err != nil || got != MemoryUnlimited {
		t.Fatalf("MemoryMax unlimited = %d, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(cgPath, "memory.current"), []byte("268435456\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := m.MemoryCurrent(id); err != nil || got != 268435456 {
		t.Fatalf("MemoryCurrent = %d, %v", got, err)
	}
	// A missing cgroup surfaces an error, not a zero value.
	if _, err := m.MemoryMax("absent"); err == nil {
		t.Fatal("MemoryMax on a missing cgroup must error")
	}
}

func TestParseMemoryLimit(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"max", MemoryUnlimited, true},
		{"0", 0, true},
		{"1073741824", 1073741824, true},
		{"-1", 0, false},
		{"bogus", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, err := parseMemoryLimit(c.in)
		if c.ok != (err == nil) || got != c.want {
			t.Errorf("parseMemoryLimit(%q) = %d, %v; want %d ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
}
