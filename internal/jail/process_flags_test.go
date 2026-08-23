//go:build linux

package jail

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// TestConfigureProcessIsolation_FlagPolicy pins the clone-flag policy for the
// UML monitor. CI exercises both legs: `go test ./...` (unprivileged) and
// `sudo go test ./internal/jail/` (root), so the user-namespace expectation
// is keyed on the effective uid. See the policy comment in process_linux.go
// for the rationale of each flag.
func TestConfigureProcessIsolation_FlagPolicy(t *testing.T) {
	ResetHostCapabilitiesForTest(&HostCapabilities{
		HasLandlock: true,
		HasUserNS:   true,
		HasSeccomp:  true,
		HasMountNS:  true,
	})
	t.Cleanup(func() { ResetHostCapabilitiesForTest(nil) })

	cmd := exec.Command("true")
	if err := ConfigureProcessIsolation(cmd, &JailEnvironment{}); err != nil {
		t.Fatalf("ConfigureProcessIsolation failed: %v", err)
	}
	if cmd.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be configured")
	}

	flags := cmd.SysProcAttr.Cloneflags
	if flags&syscall.CLONE_NEWNS == 0 || flags&syscall.CLONE_NEWIPC == 0 || flags&syscall.CLONE_NEWUTS == 0 {
		t.Errorf("expected CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWUTS in flags, got %#x", flags)
	}
	if cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Errorf("expected Pdeathsig=SIGKILL, got %v", cmd.SysProcAttr.Pdeathsig)
	}

	if os.Geteuid() == 0 {
		// Privileged leg WITHOUT an allocated uid range: degraded
		// mountns-only jail (no userns, no pidns) — the legacy shape.
		if flags&syscall.CLONE_NEWUSER != 0 {
			t.Errorf("privileged run without uid range must not set CLONE_NEWUSER, got flags %#x", flags)
		}
		if flags&syscall.CLONE_NEWPID != 0 {
			t.Errorf("privileged run without uid range must not set CLONE_NEWPID, got flags %#x", flags)
		}
		if len(cmd.SysProcAttr.UidMappings) != 0 || len(cmd.SysProcAttr.GidMappings) != 0 {
			t.Errorf("privileged run without uid range must not install uid/gid mappings, got uid=%v gid=%v",
				cmd.SysProcAttr.UidMappings, cmd.SysProcAttr.GidMappings)
		}
	} else {
		// Rootless leg: the user namespace + single uid/gid mapping is the
		// point of running without privileges; the PID namespace rides along.
		if flags&syscall.CLONE_NEWUSER == 0 {
			t.Errorf("rootless run with user namespaces available must set CLONE_NEWUSER, got flags %#x", flags)
		}
		if flags&syscall.CLONE_NEWPID == 0 {
			t.Errorf("rootless run with user namespaces available must set CLONE_NEWPID, got flags %#x", flags)
		}
		if len(cmd.SysProcAttr.UidMappings) != 1 || len(cmd.SysProcAttr.GidMappings) != 1 {
			t.Errorf("rootless run expects exactly one uid and one gid mapping, got uid=%v gid=%v",
				cmd.SysProcAttr.UidMappings, cmd.SysProcAttr.GidMappings)
		}
	}
}

// TestConfigureProcessIsolation_RootlessHardBoundary pins the new privileged
// rootless policy (TODO.md "[P1] Jail rootless 化"): a privileged manager
// with an allocated uid range wraps the monitor in NEWUSER+NEWPID with a
// 65536-wide mapping onto that range.
func TestConfigureProcessIsolation_RootlessHardBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("privileged-only policy leg")
	}
	ResetHostCapabilitiesForTest(&HostCapabilities{
		HasLandlock: true,
		HasUserNS:   true,
		HasSeccomp:  true,
		HasMountNS:  true,
	})
	t.Cleanup(func() { ResetHostCapabilitiesForTest(nil) })

	cmd := exec.Command("true")
	env := &JailEnvironment{
		Config: Config{UIDBase: 100000, UIDRangeSize: 65536},
	}
	if err := ConfigureProcessIsolation(cmd, env); err != nil {
		t.Fatalf("ConfigureProcessIsolation failed: %v", err)
	}

	flags := cmd.SysProcAttr.Cloneflags
	if flags&syscall.CLONE_NEWUSER == 0 {
		t.Errorf("privileged rootless run must set CLONE_NEWUSER, got flags %#x", flags)
	}
	if flags&syscall.CLONE_NEWPID == 0 {
		t.Errorf("privileged rootless run must set CLONE_NEWPID, got flags %#x", flags)
	}
	want := []syscall.SysProcIDMap{{ContainerID: 0, HostID: 100000, Size: 65536}}
	if len(cmd.SysProcAttr.UidMappings) != 1 || cmd.SysProcAttr.UidMappings[0] != want[0] {
		t.Errorf("uid mappings = %v, want %v", cmd.SysProcAttr.UidMappings, want)
	}
	if len(cmd.SysProcAttr.GidMappings) != 1 || cmd.SysProcAttr.GidMappings[0] != want[0] {
		t.Errorf("gid mappings = %v, want %v", cmd.SysProcAttr.GidMappings, want)
	}
}
