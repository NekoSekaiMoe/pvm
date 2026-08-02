package container

import (
	"context"
	"os"
	"testing"
	"uml-container/internal/config"
	"uml-container/internal/state"
	"uml-container/internal/uml"
)

type mockLauncher struct {
	lastKernel string
	lastArgs   []string
}

func (m *mockLauncher) Start(ctx context.Context, kernel string, args []string, logFile *os.File) (int, *uml.Process, error) {
	m.lastKernel = kernel
	m.lastArgs = args
	return 12345, &uml.Process{}, nil
}

func (m *mockLauncher) Wait(p *uml.Process) error {
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

	tempDir, err := os.MkdirTemp("", "uml-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	state.RootDir = tempDir

	cgTempDir, err := os.MkdirTemp("", "uml-cgroup-test")
	if err != nil {
		t.Fatalf("failed to create cgroup temp dir: %v", err)
	}
	defer os.RemoveAll(cgTempDir)
	os.Setenv("PVM_CGROUP_ROOT", cgTempDir)
	defer os.Unsetenv("PVM_CGROUP_ROOT")

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

	err = manager.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
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

	tempDir, err := os.MkdirTemp("", "uml-test-virtio")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	state.RootDir = tempDir

	cgTempDir, err := os.MkdirTemp("", "uml-cgroup-test-virtio")
	if err != nil {
		t.Fatalf("failed to create cgroup temp dir: %v", err)
	}
	defer os.RemoveAll(cgTempDir)
	os.Setenv("PVM_CGROUP_ROOT", cgTempDir)
	defer os.Unsetenv("PVM_CGROUP_ROOT")

	cfg := &config.ContainerConfig{
		ID:         "1235",
		Name:       "test-virtio",
		Kernel:     "/usr/lib/uml/linux",
		Rootfs:     "rootfs.img",
		Memory:     "512M",
		UseVirtio:  true,
		Init:       "/sbin/init",
		NetworkTap: "tap0",
	}

	err = manager.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	expectedArgs := []string{"ubd0=rootfs.img", "root=/dev/ubda", "init=/sbin/init", "mem=512M", "eth0=tuntap,tap0"}
	for _, arg := range expectedArgs {
		if !contains(mock.lastArgs, arg) {
			t.Errorf("expected arg %s, but missing", arg)
		}
	}
}
