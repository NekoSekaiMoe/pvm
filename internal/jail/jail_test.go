package jail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectHostCapabilities(t *testing.T) {
	caps := DetectHostCapabilities()
	t.Logf("Host Capabilities: %+v", caps)
	if caps.Details == "" {
		t.Fatalf("expected non-empty details in HostCapabilities")
	}
}

func TestCheckSecurity_FailClosedByDefault(t *testing.T) {
	// Simulate environment missing Landlock and Seccomp
	simulated := &HostCapabilities{
		HasSeccomp:  false,
		HasLandlock: false,
		HasMountNS:  false,
		HasUserNS:   false,
		Details:     "simulated-insecure",
	}
	ResetHostCapabilitiesForTest(simulated)
	defer ResetHostCapabilitiesForTest(nil)

	// allowDegraded = false => must FAIL-CLOSED
	rep, err := CheckSecurity(false, true, true)
	if err == nil {
		t.Fatalf("expected fail-closed error, got report: %+v", rep)
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Errorf("expected 'fail-closed' in error, got %v", err)
	}
	if !strings.Contains(err.Error(), "--insecure-allow-degraded") {
		t.Errorf("expected bypass hint in error, got %v", err)
	}
}

func TestCheckSecurity_AllowDegraded(t *testing.T) {
	// Simulate environment missing Landlock
	simulated := &HostCapabilities{
		HasSeccomp:  true,
		HasLandlock: false,
		HasMountNS:  true,
		HasUserNS:   true,
		Details:     "simulated-no-landlock",
	}
	ResetHostCapabilitiesForTest(simulated)
	defer ResetHostCapabilitiesForTest(nil)

	// allowDegraded = true => must return degraded report without error
	rep, err := CheckSecurity(true, true, true)
	if err != nil {
		t.Fatalf("unexpected error with allowDegraded=true: %v", err)
	}
	if !rep.Degraded {
		t.Errorf("expected report.Degraded to be true")
	}
	found := false
	for _, l := range rep.BypassedLayers {
		if l == "landlock-lsm" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'landlock-lsm' in bypassed layers, got %v", rep.BypassedLayers)
	}
}

func TestSetupJail_DirectoryStructure(t *testing.T) {
	tmp := t.TempDir()
	cfg := Config{
		TaskID:  "test-task-123",
		BaseDir: filepath.Join(tmp, "jail-root"),
		Volumes: []VolumeMapping{
			{HostPath: "/tmp/host", GuestPath: "/workspace", ReadOnly: false},
		},
	}

	env, err := SetupJail(cfg)
	if err != nil {
		t.Fatalf("SetupJail failed: %v", err)
	}
	defer env.Cleanup()

	for _, sub := range []string{"volumes", "images", "sockets", "dev", "tmp"} {
		p := filepath.Join(env.JailDir, sub)
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			t.Errorf("expected directory %s to exist in jail", p)
		}
	}
}
