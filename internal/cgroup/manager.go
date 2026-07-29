package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Manager handles cgroup v2 resource limits for a container.
type Manager struct {
	CgroupRoot string
}

func NewManager() *Manager {
	return &Manager{
		CgroupRoot: "/sys/fs/cgroup/uml",
	}
}

func (m *Manager) Setup(containerID string, pid int, memory int64, cpu int) error {
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
