package container

import (
	"context"
	"fmt"
	"os"
	"time"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/log"
	"uml-container/internal/state"
	"uml-container/internal/uml"
	"uml-container/internal/vhost"
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
		// UML virtio_uml 驱动的命令行语法 (见 arch/um/drivers/virtio_uml.c):
		//   virtio_uml.device=<socket>:<virtio_id>[:<platform_id>]
		// virtio_id 取自 virtio_ids.h: 1=net, 2=block。
		// 之前用的 "virtio=0,vhost-user,socket=..." 是无效语法, 内核会
		// 当成未知参数丢弃, 导致 /dev/vda 永远不会出现、VFS 无法挂载 root。
		args = append(args, fmt.Sprintf("virtio_uml.device=%s:%d", cfg.VhostUserSocket, vhost.VirtioIDBlock))
		args = append(args, "root=/dev/vda")
	} else {
		args = append(args, fmt.Sprintf("ubd0=%s", cfg.Rootfs))
		args = append(args, "root=/dev/ubda")
	}
	// UML 默认以只读方式挂载根文件系统，而容器 init 经常需要写
	// /etc/resolv.conf、apk 缓存等。显式 rw 让根可写，与 test_integration
	// 之外所有需要写入的初始化脚本兼容。
	args = append(args, "rw=1")

	if cfg.NetworkTap != "" {
		if cfg.VhostNetSocket != "" {
			// 同上: virtio_uml.device=<socket>:<virtio_id>, net 用 VIRTIO_ID_NET。
			args = append(args, fmt.Sprintf("virtio_uml.device=%s:%d", cfg.VhostNetSocket, vhost.VirtioIDNet))
		} else if cfg.UseVirtio {
			args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,vnet=1", cfg.NetworkTap))
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

	pid, p, err := m.Launcher.Start(ctx, cfg.Kernel, args, logFile)
	st.PID = pid

	if err != nil {
		st.Status = "exited"
		state.SaveState(cfg.ID, st)
		return err
	}

	cg := cgroup.NewManager()
	if setupErr := cg.Setup(cfg.ID, pid, cfg.MemoryBytes, cfg.CPU); setupErr != nil {
		// cgroup 是可选的资源约束基础设施，不可用时不阻塞容器启动，
		// 降级为无限制运行（与 runc/crun 在 cgroup 不可用时的行为一致）。
		// 213d9d6 曾把这里改成 hard-fail+Kill，导致 CI 上 cgroup 不可写时
		// 容器一启动就被杀，故恢复为 warning。
		fmt.Printf("Warning: failed to setup cgroup limits for %s: %v\n", cfg.ID, setupErr)
	}

	st.Status = "running"
	if saveErr := state.SaveState(cfg.ID, st); saveErr != nil {
		fmt.Printf("Warning: failed to save state: %v\n", saveErr)
	}

	err = m.Launcher.Wait(p)

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
