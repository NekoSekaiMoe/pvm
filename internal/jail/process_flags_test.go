//go:build linux

package jail

import (
	"encoding/json"
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
		// mountns-only jail — stage 1 (real root) gets mount/ipc/uts only.
		if flags&syscall.CLONE_NEWUSER != 0 {
			t.Errorf("stage 1 of a privileged run must not set CLONE_NEWUSER (stage 2 enters the userns), got flags %#x", flags)
		}
		if flags&syscall.CLONE_NEWPID != 0 {
			t.Errorf("stage 1 must not set CLONE_NEWPID (stage 2 enters the pidns), got flags %#x", flags)
		}
		if len(cmd.SysProcAttr.UidMappings) != 0 || len(cmd.SysProcAttr.GidMappings) != 0 {
			t.Errorf("privileged run without uid range must not install uid/gid mappings, got uid=%v gid=%v",
				cmd.SysProcAttr.UidMappings, cmd.SysProcAttr.GidMappings)
		}
	} else {
		// Rootless leg: stage 1 gets the user namespace + single uid/gid
		// self-map (it needs the capabilities for its mount setup); the PID
		// namespace is entered by STAGE 2, so NEWPID must NOT be here.
		if flags&syscall.CLONE_NEWUSER == 0 {
			t.Errorf("rootless run with user namespaces available must set CLONE_NEWUSER, got flags %#x", flags)
		}
		if flags&syscall.CLONE_NEWPID != 0 {
			t.Errorf("stage 1 must not set CLONE_NEWPID (stage 2 enters the pidns), got flags %#x", flags)
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
	// Two-stage design: stage 1 does the mount setup as REAL ROOT in a
	// fresh mountns (no NEWUSER); stage 2 enters NEWUSER+NEWPID per the
	// JSON stage plan in the environment.
	if flags&syscall.CLONE_NEWUSER != 0 {
		t.Errorf("stage 1 of a privileged rootless run must not set CLONE_NEWUSER, got flags %#x", flags)
	}
	if flags&syscall.CLONE_NEWPID != 0 {
		t.Errorf("stage 1 of a privileged rootless run must not set CLONE_NEWPID, got flags %#x", flags)
	}
	var stageCfg *jailHelperConfig
	for _, e := range cmd.Env {
		if raw, ok := strings.CutPrefix(e, jailHelperEnvConfig+"="); ok {
			stageCfg = &jailHelperConfig{}
			if err := json.Unmarshal([]byte(raw), stageCfg); err != nil {
				t.Fatalf("decode stage config: %v", err)
			}
		}
	}
	if stageCfg == nil {
		t.Fatal("no stage config in environment")
	}
	if !stageCfg.StageUserNS || !stageCfg.StagePIDNS || !stageCfg.MountProc {
		t.Errorf("stage config = %+v, want StageUserNS+StagePIDNS+MountProc", stageCfg)
	}
	if stageCfg.UIDBase != 100000 || stageCfg.UIDRangeSize != 65536 {
		t.Errorf("stage config uid range = %d+%d, want 100000+65536", stageCfg.UIDBase, stageCfg.UIDRangeSize)
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
	// On failure the stage processes dump uid_map/capabilities/LSM label/
	// mountinfo — mount EPERM inside user namespaces has too many possible
	// causes to debug blind.
	t.Setenv("PVM_JAIL_DEBUG", "1")

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
