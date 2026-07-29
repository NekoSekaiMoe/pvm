package container

import (
	"context"
	"fmt"
	"time"
	"uml-container/internal/config"
	"uml-container/internal/log"
	"uml-container/internal/state"
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
		if cfg.VhostUserSocket != "" {
			args = append(args, fmt.Sprintf("virtio=0,vhost-user,socket=%s", cfg.VhostUserSocket))
			args = append(args, "root=/dev/vda")
		} else {
			args = append(args, fmt.Sprintf("ubd0=%s", cfg.Rootfs))
			args = append(args, "root=/dev/ubda")
		}
	} else {
		args = append(args, fmt.Sprintf("ubd0=%s", cfg.Rootfs))
		args = append(args, "root=/dev/ubda")
	}

	if cfg.NetworkTap != "" {
		if cfg.UseVirtio {
			args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s", cfg.NetworkTap))
		} else {
			args = append(args, fmt.Sprintf("eth0=tuntap,%s", cfg.NetworkTap))
		}
	}

	// Feature 3: setup logs
	logFile, err := log.SetupConsoleLog(cfg.ID)
	if err == nil {
		defer logFile.Close()
	} else {
		fmt.Printf("Warning: could not setup log file: %v\n", err)
	}

	// Feature 2: state (pre-launch)
	state.SaveState(cfg.ID, &state.ContainerState{
		ID:        cfg.ID,
		Status:    "starting",
		StartedAt: time.Now(),
	})

	err = m.Launcher.Launch(ctx, cfg.Kernel, args, logFile)

	// State post-launch
	if err != nil {
		state.SaveState(cfg.ID, &state.ContainerState{ID: cfg.ID, Status: "stopped"})
	} else {
		state.SaveState(cfg.ID, &state.ContainerState{ID: cfg.ID, Status: "exited"})
	}

	return err
}
