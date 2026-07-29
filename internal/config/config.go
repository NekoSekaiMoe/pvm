package config

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
