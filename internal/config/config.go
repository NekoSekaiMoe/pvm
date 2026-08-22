package config

import (
	"fmt"
	"math"
)

type ContainerConfig struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kernel    string `json:"kernel"`
	Rootfs    string `json:"rootfs"`
	Memory    string `json:"memory"`     // e.g. 512M
	MemoryBytes int64  `json:"memory_bytes"` // For cgroups
	CPU       int    `json:"cpu"`
	Init      string `json:"init"`
	
	// virtio and network options
	UseVirtio       bool   `json:"use_virtio"`
	VhostUserSocket string `json:"vhost_user_socket"`
	NetworkTap      string `json:"network_tap"`

	// Ephemeral boots the rootfs read-only (kernel cmdline "ro"): nothing
	// the guest writes persists. The legacy Start path has no overlay to
	// skip, so this is purely the ro/rw cmdline switch (umlctl -ephemeral
	// additionally discards the container dir after exit).
	Ephemeral bool `json:"ephemeral"`
}

// ParseMemory parses strings like "512M", "1G" into bytes
func ParseMemory(mem string) (int64, error) {
	if mem == "" {
		return 0, fmt.Errorf("memory cannot be empty")
	}
	var val int64
	var unit string
	if _, err := fmt.Sscanf(mem, "%d%s", &val, &unit); err != nil {
		return 0, fmt.Errorf("invalid memory format: %s", mem)
	}
	if val < 0 {
		return 0, fmt.Errorf("memory cannot be negative")
	}
	switch unit {
	case "K", "k", "KB", "kb":
		if val > math.MaxInt64/1024 {
			return 0, fmt.Errorf("memory value overflow")
		}
		val = val * 1024
	case "M", "m", "MB", "mb":
		if val > math.MaxInt64/(1024*1024) {
			return 0, fmt.Errorf("memory value overflow")
		}
		val = val * 1024 * 1024
	case "G", "g", "GB", "gb":
		if val > math.MaxInt64/(1024*1024*1024) {
			return 0, fmt.Errorf("memory value overflow")
		}
		val = val * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unsupported or missing memory unit: %s", unit)
	}
	return val, nil
}
