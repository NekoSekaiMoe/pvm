//go:build linux

package jail

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	// The jail helper pivots into Rootfs, so the workload sees the volume at
	// its guest path; writes there must land back on the host path.
	cmd := exec.Command("touch", "/workspace/subtest")
	if err := ConfigureProcessIsolation(cmd, env); err != nil {
		t.Fatalf("ConfigureProcessIsolation failed: %v", err)
	}

	// The two-stage launch blocks stage 1 on the launch-sync pipe until
	// the manager confirms post-fork setup — in tests, that is us.
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	env.SignalReady()
	err := cmd.Wait()
	out := buf.Bytes()
	if err != nil {
		if os.Geteuid() != 0 {
			// Known case: unprivileged CI containers without user-namespace
			// permissions cannot create CLONE_NEWUSER/CLONE_NEWNS at runtime.
			t.Skipf("skipping unprivileged namespace execution (container without user namespace permissions): %v, output: %s", err, string(out))
		}
		// Privileged callers always may unshare; a failure here means the
		// isolation setup itself is broken and must not be waved through.
		t.Fatalf("privileged namespace execution failed: %v, output: %s", err, string(out))
	}

	testFile := filepath.Join(tmp, "subtest")
	if _, err := os.Stat(testFile); err != nil {
		t.Fatalf("expected jailed write to land on host volume path %s: %v", testFile, err)
	}
}

// TestJailHelper_FailsClosedWithoutPrivileges pins the error-propagation
// contract of the re-exec helper: when the mounts cannot be set up (here:
// no CAP_SYS_ADMIN and no user namespace), the helper must exit non-zero
// with a clear diagnostic BEFORE the workload binary is exec'd.
func TestJailHelper_FailsClosedWithoutPrivileges(t *testing.T) {
	if os.Geteuid() == 0 {
		// As root the first mount would succeed and — without CLONE_NEWNS —
		// mutate the mount namespace shared with the test runner. The real
		// launch path always pairs the helper with CLONE_NEWNS, so only
		// exercise the failure leg unprivileged.
		t.Skip("helper fail-closed leg is only safe to probe unprivileged")
	}

	cfg := jailHelperConfig{
		Rootfs: t.TempDir(),
		Target: "/bin/true",
		Args:   []string{"true"},
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal helper config: %v", err)
	}

	// The helper branch runs from init() in the re-exec'd binary, so it fires
	// before the test framework regardless of -test.run.
	cmd := exec.Command(os.Args[0], "-test.run=TestJailHelperSentinel")
	cmd.Env = append(os.Environ(),
		jailHelperEnvMarker+"=1",
		jailHelperEnvConfig+"="+string(blob),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("helper must fail without mount privileges; it ran the workload. output: %s", string(out))
	}
	if !strings.Contains(string(out), "jail helper:") {
		t.Errorf("expected a clear 'jail helper:' diagnostic, got: %s", string(out))
	}
}
