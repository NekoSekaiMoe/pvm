package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

var validContainerID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Manager handles cgroup v2 resource limits for a container.
type Manager struct {
	CgroupRoot string
}

// defaultCgroupRoot is the production cgroup v2 mount used when no override
// is provided. It can be overridden via the PVM_CGROUP_ROOT or CGROUP_ROOT
// environment variables (the latter is kept for compatibility with the
// integration shell tests), which is required for non-root test runs.
const defaultCgroupRoot = "/sys/fs/cgroup/uml"

func NewManager() *Manager {
	return &Manager{
		CgroupRoot: resolveCgroupRoot(),
	}
}

// resolveCgroupRoot picks the cgroup root from the environment when available
// so tests and the CLI can target a throwaway directory without root.
func resolveCgroupRoot() string {
	if v := os.Getenv("PVM_CGROUP_ROOT"); v != "" {
		return v
	}
	if v := os.Getenv("CGROUP_ROOT"); v != "" {
		return v
	}
	return defaultCgroupRoot
}

func (m *Manager) Setup(containerID string, pid int, memory int64, cpu int) error {
	if !validContainerID.MatchString(containerID) {
		return fmt.Errorf("invalid container ID")
	}
	cgPath := filepath.Join(m.CgroupRoot, containerID)
	if err := os.MkdirAll(cgPath, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup directory: %v", err)
	}

	// Move pid to cgroup
	procsFile := filepath.Join(cgPath, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to write cgroup.procs: %v", err)
	}

	// Set memory limit if provided
	if memory > 0 {
		memFile := filepath.Join(cgPath, "memory.max")
		if err := os.WriteFile(memFile, []byte(strconv.FormatInt(memory, 10)), 0644); err != nil {
			return fmt.Errorf("failed to write memory.max: %v", err)
		}
	}

	// Set CPU limit if provided (cgroup v2 cpu.max format: "MAX PERIOD")
	if cpu > 0 {
		if cpu > 1024 {
			return fmt.Errorf("cpu limit exceeds maximum allowed value")
		}
		cpuFile := filepath.Join(cgPath, "cpu.max")
		// e.g. 1 cpu = "100000 100000"
		quota := cpu * 100000
		val := fmt.Sprintf("%d 100000", quota)
		if err := os.WriteFile(cpuFile, []byte(val), 0644); err != nil {
			return fmt.Errorf("failed to write cpu.max: %v", err)
		}
	}

	return nil
}

// Freeze suspends all processes in the cgroup
func (m *Manager) Freeze(containerID string) error {
	if !validContainerID.MatchString(containerID) {
		return fmt.Errorf("invalid container ID")
	}
	cgPath := filepath.Join(m.CgroupRoot, containerID)
	freezeFile := filepath.Join(cgPath, "cgroup.freeze")
	return os.WriteFile(freezeFile, []byte("1"), 0644)
}

// Thaw resumes all processes in the cgroup
func (m *Manager) Thaw(containerID string) error {
	if !validContainerID.MatchString(containerID) {
		return fmt.Errorf("invalid container ID")
	}
	cgPath := filepath.Join(m.CgroupRoot, containerID)
	freezeFile := filepath.Join(cgPath, "cgroup.freeze")
	return os.WriteFile(freezeFile, []byte("0"), 0644)
}
