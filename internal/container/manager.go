package container

import (
	"context"
	"fmt"
	"uml-container/internal/config"
	"uml-container/internal/uml"
)

type Manager struct {
	Launcher uml.Launcher
}

func NewManager(launcher uml.Launcher) *Manager {
	if launcher == nil {
		launcher = &uml.DefaultLauncher{}
	}
	return &Manager{Launcher: launcher}
}

func (m *Manager) Start(ctx context.Context, cfg *config.ContainerConfig) error {
	args := []string{
		fmt.Sprintf("init=%s", cfg.Init),
		fmt.Sprintf("mem=%s", cfg.Memory),
	}

	if cfg.UseVirtio {
		// Use virtio for block and network
		if cfg.VhostUserSocket != "" {
			args = append(args, fmt.Sprintf("virtio=0,vhost-user,socket=%s", cfg.VhostUserSocket))
			args = append(args, "root=/dev/vda")
		} else {
			// Fallback: pretend virtio block config if socket missing
			args = append(args, fmt.Sprintf("ubd0=%s", cfg.Rootfs))
			args = append(args, "root=/dev/ubda")
		}
	} else {
		// Use traditional UML drivers
		args = append(args, fmt.Sprintf("ubd0=%s", cfg.Rootfs))
		args = append(args, "root=/dev/ubda")
	}

	if cfg.NetworkTap != "" {
		if cfg.UseVirtio {
			// e.g. virtio_net or vector driver over tap
			args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s", cfg.NetworkTap))
		} else {
			// Traditional UML network
			args = append(args, fmt.Sprintf("eth0=tuntap,%s", cfg.NetworkTap))
		}
	}

	return m.Launcher.Launch(ctx, cfg.Kernel, args)
}
