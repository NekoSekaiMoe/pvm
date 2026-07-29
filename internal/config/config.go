package config

import "fmt"

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
}

// ParseMemory parses strings like "512M", "1G" into bytes
func ParseMemory(mem string) int64 {
	var val int64
	var unit string
	if _, err := fmt.Sscanf(mem, "%d%s", &val, &unit); err != nil {
		return 0
	}
	switch unit {
	case "K", "k", "KB", "kb":
		return val * 1024
	case "M", "m", "MB", "mb":
		return val * 1024 * 1024
	case "G", "g", "GB", "gb":
		return val * 1024 * 1024 * 1024
	default:
		return val
	}
}
