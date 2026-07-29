package container

import (
	"context"
	"fmt"
	"os"
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

	// Direct shell interactive setup uses con0
	interactive, _ := ctx.Value("interactive").(bool)
	if interactive {
		args = append(args, "con0=fd:0,fd:1")
		args = append(args, "con=null")
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

	// hostfs volume mounting
	vHost, hasVHost := ctx.Value("volume_host").(string)
	vGuest, hasVGuest := ctx.Value("volume_guest").(string)
	if hasVHost && hasVGuest {
		// Just demonstrate the mount string. To actually mount this inside UML guest at boot without systemd
		// requires passing custom rootflags or an init script. UML uses hostfs via rootfstype=hostfs.
		// For MVP, we pass it as a kernel cmdline arg and assume init.sh script mounts it:
		// "mount -t hostfs hostfs $VGUEST -o $VHOST"
		args = append(args, fmt.Sprintf("hostfs_volume=%s:%s", vHost, vGuest))
	}

	var logFile *os.File
	if !interactive {
		var err error
		logFile, err = log.SetupConsoleLog(cfg.ID)
		if err == nil {
			defer logFile.Close()
		} else {
			fmt.Printf("Warning: could not setup log file: %v\n", err)
		}
	}

	state.SaveState(cfg.ID, &state.ContainerState{
		ID:        cfg.ID,
		Status:    "starting",
		StartedAt: time.Now(),
	})

	err := m.Launcher.Launch(ctx, cfg.Kernel, args, logFile)

	if err != nil {
		state.SaveState(cfg.ID, &state.ContainerState{ID: cfg.ID, Status: "stopped"})
	} else {
		state.SaveState(cfg.ID, &state.ContainerState{ID: cfg.ID, Status: "exited"})
	}

	return err
}
