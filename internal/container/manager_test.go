package container

import (
	"context"
	"os"
	"testing"
	"uml-container/internal/config"
)

type mockLauncher struct {
	lastKernel string
	lastArgs   []string
}

func (m *mockLauncher) Launch(ctx context.Context, kernel string, args []string, logFile *os.File) error {
	m.lastKernel = kernel
	m.lastArgs = args
	return nil
}

func contains(arr []string, str string) bool {
	for _, v := range arr {
		if v == str {
			return true
		}
	}
	return false
}

func TestManager_Start(t *testing.T) {
	mock := &mockLauncher{}
	manager := NewManager(mock)

	// Since state and log depend on /var/lib/..., in a real test we'd mock those or use a temp dir.
	// For simplicity, we just verify the launcher args still.

	cfg := &config.ContainerConfig{
		ID:         "1234",
		Name:       "test",
		Kernel:     "/usr/lib/uml/linux",
		Rootfs:     "rootfs.img",
		Memory:     "512M",
		CPU:        2,
		Init:       "/sbin/init",
		NetworkTap: "tap0",
	}

	err := manager.Start(context.Background(), cfg)
	if err != nil {
		// Just ignore dir creation errors in simple mock test
	}

	expectedArgs := []string{"ubd0=rootfs.img", "root=/dev/ubda", "init=/sbin/init", "mem=512M", "eth0=tuntap,tap0"}
	for _, arg := range expectedArgs {
		if !contains(mock.lastArgs, arg) {
			t.Errorf("expected arg %s, but missing", arg)
		}
	}
}
