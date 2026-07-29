package container

import (
	"context"
	"testing"
	"uml-container/internal/config"
)

type mockLauncher struct {
	lastKernel string
	lastArgs   []string
}

func (m *mockLauncher) Launch(ctx context.Context, kernel string, args []string) error {
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
		t.Fatalf("unexpected error: %v", err)
	}

	expectedArgs := []string{"ubd0=rootfs.img", "root=/dev/ubda", "init=/sbin/init", "mem=512M", "eth0=tuntap,tap0"}
	for _, arg := range expectedArgs {
		if !contains(mock.lastArgs, arg) {
			t.Errorf("expected arg %s, but missing", arg)
		}
	}
}

func TestManager_Start_Virtio(t *testing.T) {
	mock := &mockLauncher{}
	manager := NewManager(mock)

	cfg := &config.ContainerConfig{
		ID:              "1234",
		Kernel:          "/usr/lib/uml/linux",
		Rootfs:          "rootfs.img",
		Memory:          "512M",
		Init:            "/sbin/init",
		UseVirtio:       true,
		VhostUserSocket: "/tmp/vhost.sock",
		NetworkTap:      "tap0",
	}

	err := manager.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedArgs := []string{"virtio=0,vhost-user,socket=/tmp/vhost.sock", "root=/dev/vda", "init=/sbin/init", "mem=512M", "vec0:transport=tap,ifname=tap0"}
	for _, arg := range expectedArgs {
		if !contains(mock.lastArgs, arg) {
			t.Errorf("expected arg %s, but missing in virtio test", arg)
		}
	}
}
