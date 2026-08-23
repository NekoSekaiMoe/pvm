//go:build linux

package jail

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	cmd := exec.Command("/bin/true")
	if err := ConfigureProcessIsolation(cmd, &JailEnvironment{Rootfs: t.TempDir()}); err != nil {
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

	cmd := exec.Command("/bin/true")
	env := &JailEnvironment{
		Config: Config{UIDBase: 100000, UIDRangeSize: 65536},
		Rootfs: t.TempDir(),
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

// TestRootlessJail_Execution runs the FULL jail path (namespace clone with
// NEWUSER+NEWPID, fd hand-over, helper pivot_root, private /proc mount,
// Landlock, capability drop, seccomp, workload exec) as root, exactly the
// way the manager launches UML in production. It exists because flag-only
// tests cannot see helper-time failures (bind sources, /proc mount,
// Landlock rules on procfs): the CI privileged leg (sudo go test
// ./internal/jail/) executes this on every run.
func TestRootlessJail_Execution(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("privileged-only execution leg")
	}
	caps := DetectHostCapabilities()
	if !caps.HasUserNS || !caps.HasMountNS {
		t.Skip("host lacks user/mount namespaces")
	}

	env, err := SetupJail(Config{
		TaskID:       "rootless-exec-test",
		BaseDir:      filepath.Join(t.TempDir(), "jail"),
		UIDBase:      100000,
		UIDRangeSize: 65536,
	})
	if err != nil {
		t.Fatalf("SetupJail: %v", err)
	}
	t.Cleanup(func() { env.Cleanup() })

	cmd := exec.Command("/bin/sh", "-c",
		`echo JAIL_OK; echo NS_PID=$$; [ -d /proc/self ] && echo PROC_OK || echo PROC_MISSING; `+
			`kill -TERM 2 2>/dev/null || echo HOST_PID2_UNREACHABLE`)
	if err := ConfigureProcessIsolation(cmd, env); err != nil {
		t.Fatalf("ConfigureProcessIsolation: %v", err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rootless jailed execution failed: %v, output: %s", err, out)
	}
	for _, want := range []string{"JAIL_OK", "NS_PID=1", "PROC_OK", "HOST_PID2_UNREACHABLE"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("expected %q in jailed workload output, got:\n%s", want, out)
		}
	}
}
