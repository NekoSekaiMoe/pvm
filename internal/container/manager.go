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

type ContextKey string

const (
	KeyInteractive ContextKey = "interactive"
	KeyVolumeHost  ContextKey = "volume_host"
	KeyVolumeGuest ContextKey = "volume_guest"
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
	interactive, _ := ctx.Value(KeyInteractive).(bool)
	if interactive {
		args = append(args, "con0=fd:0,fd:1")
		args = append(args, "con=null")
	}

	if cfg.UseVirtio && cfg.VhostUserSocket != "" {
		args = append(args, fmt.Sprintf("virtio=0,vhost-user,socket=%s", cfg.VhostUserSocket))
		args = append(args, "root=/dev/vda")
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
	vHost, hasVHost := ctx.Value(KeyVolumeHost).(string)
	vGuest, hasVGuest := ctx.Value(KeyVolumeGuest).(string)
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

	st, err := state.LoadState(cfg.ID)
	if err != nil {
		st = &state.ContainerState{
			ID:        cfg.ID,
			StartedAt: time.Now(),
		}
	}
	st.Status = "starting"
	if saveErr := state.SaveState(cfg.ID, st); saveErr != nil {
		fmt.Printf("Warning: failed to save state: %v\n", saveErr)
	}

	pid, cmd, err := m.Launcher.Start(ctx, cfg.Kernel, args, logFile)
	st.PID = pid

	if err != nil {
		st.Status = "exited"
		state.SaveState(cfg.ID, st)
		return err
	}

	st.Status = "running"
	if saveErr := state.SaveState(cfg.ID, st); saveErr != nil {
		fmt.Printf("Warning: failed to save state: %v\n", saveErr)
	}

	err = m.Launcher.Wait(cmd)

	if err != nil {
		st.Status = "exited"
	} else {
		st.Status = "stopped"
	}

	if saveErr := state.SaveState(cfg.ID, st); saveErr != nil {
		fmt.Printf("Warning: failed to save state: %v\n", saveErr)
	}

	return err
}
