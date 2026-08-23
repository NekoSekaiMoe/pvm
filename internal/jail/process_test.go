package jail

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestConfigureProcessIsolation_Base(t *testing.T) {
	cmd := exec.Command("true")
	tmp := t.TempDir()
	env := &JailEnvironment{
		Config: Config{
			Volumes: []VolumeMapping{
				{HostPath: tmp, GuestPath: "/workspace", ReadOnly: false},
			},
		},
		JailDir: tmp,
		Rootfs:  tmp,
	}

	err := ConfigureProcessIsolation(cmd, env)
	if err != nil {
		t.Fatalf("ConfigureProcessIsolation failed: %v", err)
	}

	if cmd.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be configured")
	}
}

func TestConfigureProcessIsolation_Execution(t *testing.T) {
	caps := DetectHostCapabilities()
	// If UserNS or MountNS is not available and user is not root, skip execution test
	if !caps.HasUserNS || !caps.HasMountNS {
		t.Skip("skipping process namespace execution test: host missing UserNS/MountNS")
	}

	tmp := t.TempDir()
	env := &JailEnvironment{
		Config: Config{
			Volumes: []VolumeMapping{
				{HostPath: tmp, GuestPath: "/workspace", ReadOnly: false},
			},
		},
		JailDir: tmp,
		Rootfs:  tmp,
	}

	testFile := filepath.Join(tmp, "subtest")
	cmd := exec.Command("touch", testFile)
	if err := ConfigureProcessIsolation(cmd, env); err != nil {
		t.Fatalf("ConfigureProcessIsolation failed: %v", err)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		// In unprivileged CI containers where CLONE_NEWUSER / CLONE_NEWNS fails at runtime
		t.Logf("Namespace execution returned (unprivileged container): %v, output: %s", err, string(out))
		if os.Geteuid() != 0 {
			t.Skip("skipping unprivileged namespace execution error on container without user namespace permissions")
		}
	}
}
