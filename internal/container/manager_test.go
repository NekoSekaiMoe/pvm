package container

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"uml-container/internal/config"
	"uml-container/internal/jail"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/uml"
)

func TestMain(m *testing.M) {
	jail.ResetHostCapabilitiesForTest(&jail.HostCapabilities{
		HasLandlock: true,
		HasUserNS:   true,
		HasMountNS:  true,
		HasSeccomp:  true,
		Details:     "test-simulated-full",
	})
	code := m.Run()
	jail.ResetHostCapabilitiesForTest(nil)
	os.Exit(code)
}

type mockLauncher struct {
	lastKernel string
	lastArgs   []string
}

func (m *mockLauncher) Start(ctx context.Context, kernel string, args []string, logFile io.Writer) (int, *uml.Process, error) {
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
	jail.ResetHostCapabilitiesForTest(&jail.HostCapabilities{
		HasLandlock: true,
		HasUserNS:   true,
		HasMountNS:  true,
		HasSeccomp:  true,
		Details:     "test-simulated-full",
	})
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

	// validateRootfs resolves symlinks and requires a regular file: boot a
	// real image; with the jail active the cmdline carries the in-jail path.
	rootfs := filepath.Join(tempDir, "rootfs.img")
	if err := os.WriteFile(rootfs, []byte("img"), 0600); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	if _, err := filepath.EvalSymlinks(rootfs); err != nil {
		t.Fatalf("resolve rootfs: %v", err)
	}

	cfg := &config.ContainerConfig{
		ID:         "1234",
		Name:       "test",
		Kernel:     "/usr/lib/uml/linux",
		Rootfs:     rootfs,
		Memory:     "512M",
		CPU:        2,
		Init:       "/sbin/init",
		NetworkTap: "tap0",
	}

	err = manager.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// TestMain pins full host capabilities, so the jail is active and the
	// kernel cmdline carries the IN-JAIL bind-mount path for the rootfs;
	// the resolved host path moves into the jail volume mapping (covered by
	// manager_jail_test.go).
	expectedArgs := []string{"ubd0=" + jailGuestRootfs, "root=/dev/ubda", "init=/sbin/init", "mem=512M", "vec0:transport=tap,ifname=tap0,depth=128,gro=1"}
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

	rootfs := filepath.Join(tempDir, "rootfs.img")
	if err := os.WriteFile(rootfs, []byte("img"), 0600); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	if _, err := filepath.EvalSymlinks(rootfs); err != nil {
		t.Fatalf("resolve rootfs: %v", err)
	}

	cfg := &config.ContainerConfig{
		ID:         "1235",
		Name:       "test-virtio",
		Kernel:     "/usr/lib/uml/linux",
		Rootfs:     rootfs,
		Memory:     "512M",
		UseVirtio:  true,
		Init:       "/sbin/init",
		NetworkTap: "tap0",
	}

	err = manager.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Jail active (TestMain pins capabilities): rootfs arg uses the in-jail path.
	expectedArgs := []string{"ubd0=" + jailGuestRootfs, "root=/dev/ubda", "init=/sbin/init", "mem=512M", "vec0:transport=tap,ifname=tap0,depth=128,gro=1"}
	for _, arg := range expectedArgs {
		if !contains(mock.lastArgs, arg) {
			t.Errorf("expected arg %s, but missing", arg)
		}
	}
}

func TestResolveAutoDataplane(t *testing.T) {
	mk := func(f func(s *spec.TaskSpec)) *spec.TaskSpec {
		s := &spec.TaskSpec{Version: 1, Caller: "x"}
		s.Network.Enabled = true
		f(s)
		return s
	}
	if got := resolveAutoDataplane(mk(func(s *spec.TaskSpec) {
		s.Network.PortMappings = []spec.PortMappingSpec{{HostPort: 80, GuestPort: 80}}
	})); got != spec.DataplaneBridge {
		t.Fatalf("port mappings must pin bridge, got %s", got)
	}
	if got := resolveAutoDataplane(mk(func(s *spec.TaskSpec) {
		s.Network.EgressAllowDomains = []string{"example.com"}
	})); got != spec.DataplaneBridge {
		t.Fatalf("L7 domains must pin bridge, got %s", got)
	}
	if got := resolveAutoDataplane(mk(func(s *spec.TaskSpec) {
		s.Network.EgressRules = []spec.EgressRule{{Name: "r"}}
	})); got != spec.DataplaneBridge {
		t.Fatalf("L7 rules must pin bridge, got %s", got)
	}
	// No pinning: root prefers tc, non-root falls back to bridge.
	want := spec.DataplaneTC
	if os.Geteuid() != 0 {
		want = spec.DataplaneBridge
	}
	if got := resolveAutoDataplane(mk(func(s *spec.TaskSpec) {})); got != want {
		t.Fatalf("unpinned auto = %s, want %s", got, want)
	}
}
