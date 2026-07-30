package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

	// cgroup v2 要求从根到叶子每一层都在 cgroup.subtree_control 里启用相应
	// controller，否则 memory.max / cpu.max 不可写（EACCES，root 也不行）。
	// 在 CI / 未 delegation 的主机上 /sys/fs/cgroup/uml 是我们手动 mkdir 的，
	// 没人给它启用 controller。这里尽力启用：失败不 fatal，交给上层 fallback。
	if err := m.enableControllers(memory > 0, cpu > 0); err != nil {
		return fmt.Errorf("cgroup controllers not delegated under %s: %v (consider running under a delegated scope)", m.CgroupRoot, err)
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

// enableControllers walks from the cgroup v2 root (/sys/fs/cgroup) down to
// CgroupRoot and enables the requested controllers on each ancestor's
// cgroup.subtree_control. This is necessary because memory.max/cpu.max on a
// leaf cgroup are only writable when every level above has the controller
// enabled. We do NOT require systemd; root can write the root cgroup's
// subtree_control as long as the root cgroup itself has no processes (which is
// the case on systemd-managed hosts where everything lives in a slice).
//
// Missing files / permission errors are returned so the caller can fall back
// to running without limits rather than failing hard.
func (m *Manager) enableControllers(wantMemory, wantCPU bool) error {
	if !wantMemory && !wantCPU {
		return nil
	}

	// Build the list of ancestor directories from the v2 root down to CgroupRoot.
	root := "/sys/fs/cgroup"
	cgRootAbs, err := filepath.Abs(m.CgroupRoot)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, cgRootAbs)
	if err != nil {
		// CgroupRoot is outside /sys/fs/cgroup (e.g. test override). In that case
		// there is nothing to delegate; the test harness sets it up.
		return nil
	}
	// 测试常用 /tmp 下的临时目录，不在真实 cgroup 层级内，不碰真实 /sys/fs/cgroup。
	if strings.HasPrefix(rel, "..") {
		return nil
	}

	var names []string
	if rel != "." {
		names = strings.Split(rel, string(filepath.Separator))
	}

	// Decide which controllers to enable based on what the requested limits
	// actually need and what the v2 root actually offers.
	avail, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read root cgroup.controllers: %v", err)
	}
	availStr := string(avail)

	var toEnable []string
	if wantMemory && strings.Contains(availStr, "memory") {
		toEnable = append(toEnable, "+memory")
	}
	if wantCPU && strings.Contains(availStr, "cpu") {
		toEnable = append(toEnable, "+cpu")
	}
	if len(toEnable) == 0 {
		// Nothing we can enable; let the subsequent memory.max/cpu.max write
		// produce the canonical error.
		return nil
	}
	val := strings.Join(toEnable, " ")

	// Enable on the root first, then each intermediate level. The leaf
	// (CgroupRoot itself) does not need its own subtree_control because the
	// container cgroup is the one we write limits into — but enabling on the
	// leaf is harmless and keeps the chain consistent for deeper nesting.
	cur := root
	levels := append([]string{}, names...)
	levels = append(levels, "") // include CgroupRoot itself
	for _, name := range levels {
		sc := filepath.Join(cur, "cgroup.subtree_control")
		if err := os.WriteFile(sc, []byte(val), 0644); err != nil {
			// If this level is not writable (e.g. owned by systemd), report it;
			// the caller decides whether to fall back.
			return fmt.Errorf("enable %q on %s: %v", val, sc, err)
		}
		if name != "" {
			cur = filepath.Join(cur, name)
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
