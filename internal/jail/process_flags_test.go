//go:build linux

package jail

import (
	"os/exec"
	"os"
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
	if flags&syscall.CLONE_NEWPID != 0 {
		t.Errorf("CLONE_NEWPID must never be applied to the UML monitor "+
			"(pidns init breaks supervision semantics, see process_linux.go), got flags %#x", flags)
	}
	if flags&syscall.CLONE_NEWNS == 0 || flags&syscall.CLONE_NEWIPC == 0 || flags&syscall.CLONE_NEWUTS == 0 {
		t.Errorf("expected CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWUTS in flags, got %#x", flags)
	}
	if cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Errorf("expected Pdeathsig=SIGKILL, got %v", cmd.SysProcAttr.Pdeathsig)
	}

	if os.Geteuid() == 0 {
		// Privileged leg: a user namespace would strictly remove capabilities
		// (namespaced root holds none in init_user_ns) — it must be off.
		if flags&syscall.CLONE_NEWUSER != 0 {
			t.Errorf("privileged run must not wrap the monitor in CLONE_NEWUSER, got flags %#x", flags)
		}
		if len(cmd.SysProcAttr.UidMappings) != 0 || len(cmd.SysProcAttr.GidMappings) != 0 {
			t.Errorf("privileged run must not install uid/gid mappings, got uid=%v gid=%v",
				cmd.SysProcAttr.UidMappings, cmd.SysProcAttr.GidMappings)
		}
	} else {
		// Rootless leg: the user namespace + single uid/gid mapping is the
		// point of running without privileges.
		if flags&syscall.CLONE_NEWUSER == 0 {
			t.Errorf("rootless run with user namespaces available must set CLONE_NEWUSER, got flags %#x", flags)
		}
		if len(cmd.SysProcAttr.UidMappings) != 1 || len(cmd.SysProcAttr.GidMappings) != 1 {
			t.Errorf("rootless run expects exactly one uid and one gid mapping, got uid=%v gid=%v",
				cmd.SysProcAttr.UidMappings, cmd.SysProcAttr.GidMappings)
		}
	}
}
