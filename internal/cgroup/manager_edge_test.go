package cgroup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestManager_Setup_RejectsInvalidID makes sure a hostile container id can
// never escape CgroupRoot via path traversal or shell metacharacters.
func TestManager_Setup_RejectsInvalidID(t *testing.T) {
	m := &Manager{CgroupRoot: t.TempDir()}
	for _, id := range []string{"../evil", "a/b", "bad id", "x;rm -rf /", ".hidden", ""} {
		if err := m.Setup(id, 1234, 0, 0); err == nil {
			t.Errorf("Setup(%q) = nil, want invalid container ID error", id)
		} else if !strings.Contains(err.Error(), "invalid container ID") {
			t.Errorf("Setup(%q) error = %q, want invalid container ID", id, err)
		}
	}
}

// TestManager_Setup_WritesLimits exercises the happy path against a scratch
// cgroup root: procs assignment, memory.max and cpu.max must all land with
// the exact cgroup v2 encodings.
func TestManager_Setup_WritesLimits(t *testing.T) {
	root := t.TempDir()
	m := &Manager{CgroupRoot: root}

	const (
		pid    = 4321
		memory = 64 * 1024 * 1024 // 64 MiB
		cpu    = 2
	)
	if err := m.Setup("ctr-limits", pid, memory, cpu); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	cgPath := filepath.Join(root, "ctr-limits")

	assertFile := func(name, want string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(cgPath, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			return
		}
		if string(data) != want {
			t.Errorf("%s = %q, want %q", name, data, want)
		}
	}
	assertFile("cgroup.procs", "4321")
	assertFile("memory.max", "67108864")
	// cgroup v2 cpu.max format: "MAX PERIOD" — N cpus = N*100000 over 100000.
	assertFile("cpu.max", "200000 100000")
}

// TestManager_Setup_NoLimitsSkipsControllerFiles: with memory=0 and cpu=0 the
// manager must only place the pid, never create memory.max / cpu.max.
func TestManager_Setup_NoLimitsSkipsControllerFiles(t *testing.T) {
	root := t.TempDir()
	m := &Manager{CgroupRoot: root}

	if err := m.Setup("ctr-nolimit", 999, 0, 0); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	cgPath := filepath.Join(root, "ctr-nolimit")
	for _, f := range []string{"memory.max", "cpu.max"} {
		if _, err := os.Stat(filepath.Join(cgPath, f)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist when the limit is 0", f)
		}
	}
	if data, err := os.ReadFile(filepath.Join(cgPath, "cgroup.procs")); err != nil || string(data) != "999" {
		t.Errorf("cgroup.procs = %q, %v; want \"999\"", data, err)
	}
}

// TestManager_Setup_CPUAboveMax is rejected before cpu.max is written.
func TestManager_Setup_CPUAboveMax(t *testing.T) {
	root := t.TempDir()
	m := &Manager{CgroupRoot: root}

	err := m.Setup("ctr-bigcpu", 1, 0, 2048)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("Setup(cpu=2048) error = %v, want exceeds maximum", err)
	}
	if _, serr := os.Stat(filepath.Join(root, "ctr-bigcpu", "cpu.max")); !os.IsNotExist(serr) {
		t.Error("cpu.max must not be written for an out-of-range limit")
	}
}

// TestManager_FreezeThaw_MissingContainer: freeze/thaw of a container whose
// cgroup directory was never set up must fail, not silently succeed.
func TestManager_FreezeThaw_MissingContainer(t *testing.T) {
	m := &Manager{CgroupRoot: t.TempDir()}
	if err := m.Freeze("no-such-ctr"); err == nil {
		t.Error("Freeze on missing cgroup = nil, want error")
	}
	if err := m.Thaw("no-such-ctr"); err == nil {
		t.Error("Thaw on missing cgroup = nil, want error")
	}
}

// TestResolveCgroupRoot_EnvPrecedence: PVM_CGROUP_ROOT wins over the legacy
// CGROUP_ROOT, which wins over the compiled-in default.
func TestResolveCgroupRoot_EnvPrecedence(t *testing.T) {
	// Snapshot and clear both vars so each subtest starts clean.
	origPVM, hadPVM := os.LookupEnv("PVM_CGROUP_ROOT")
	origLegacy, hadLegacy := os.LookupEnv("CGROUP_ROOT")
	os.Unsetenv("PVM_CGROUP_ROOT")
	os.Unsetenv("CGROUP_ROOT")
	t.Cleanup(func() {
		if hadPVM {
			os.Setenv("PVM_CGROUP_ROOT", origPVM)
		} else {
			os.Unsetenv("PVM_CGROUP_ROOT")
		}
		if hadLegacy {
			os.Setenv("CGROUP_ROOT", origLegacy)
		} else {
			os.Unsetenv("CGROUP_ROOT")
		}
	})

	if got := resolveCgroupRoot(); got != defaultCgroupRoot {
		t.Errorf("no env: resolveCgroupRoot() = %q, want default %q", got, defaultCgroupRoot)
	}
	os.Setenv("CGROUP_ROOT", "/tmp/legacy-cg")
	if got := resolveCgroupRoot(); got != "/tmp/legacy-cg" {
		t.Errorf("CGROUP_ROOT only: got %q, want /tmp/legacy-cg", got)
	}
	os.Setenv("PVM_CGROUP_ROOT", "/tmp/pvm-cg")
	if got := resolveCgroupRoot(); got != "/tmp/pvm-cg" {
		t.Errorf("both set: got %q, want PVM_CGROUP_ROOT to win (/tmp/pvm-cg)", got)
	}
}
