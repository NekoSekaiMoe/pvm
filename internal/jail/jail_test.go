package jail

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDetectHostCapabilities(t *testing.T) {
	caps := DetectHostCapabilities()
	t.Logf("Host Capabilities: %+v", caps)
	if caps.Details == "" {
		t.Fatalf("expected non-empty details in HostCapabilities")
	}
}

func TestCheckSecurity(t *testing.T) {
	contains := func(haystack []string, needle string) bool {
		for _, s := range haystack {
			if s == needle {
				return true
			}
		}
		return false
	}

	cases := []struct {
		name           string
		caps           HostCapabilities
		allowDegraded  bool
		enforceSeccomp bool
		enforceLand    bool
		wantErr        bool
		wantBypassed   []string // layers that MUST be reported
		forbidBypassed []string // layers that MUST NOT be reported
	}{
		{
			name: "fail closed by default",
			caps: HostCapabilities{
				HasSeccomp: false, HasLandlock: false, HasMountNS: false, HasUserNS: false,
				Details: "simulated-insecure",
			},
			allowDegraded:  false,
			enforceSeccomp: true,
			enforceLand:    true,
			wantErr:        true,
		},
		{
			name: "allow degraded missing landlock",
			caps: HostCapabilities{
				HasSeccomp: true, HasLandlock: false, HasMountNS: true, HasUserNS: true,
				Details: "simulated-no-landlock",
			},
			allowDegraded:  true,
			enforceSeccomp: true,
			enforceLand:    true,
			wantBypassed:   []string{"landlock-lsm"},
			forbidBypassed: []string{"seccomp-bpf", "namespace-isolation"},
		},
		{
			name: "only missing seccomp",
			caps: HostCapabilities{
				HasSeccomp: false, HasLandlock: true, HasMountNS: true, HasUserNS: true,
				Details: "simulated-no-seccomp",
			},
			allowDegraded:  true,
			enforceSeccomp: true,
			enforceLand:    true,
			wantBypassed:   []string{"seccomp-bpf"},
			forbidBypassed: []string{"landlock-lsm", "namespace-isolation"},
		},
		{
			// HasMountNS=false makes the namespace baseline unmet regardless of
			// the caller's euid, so this case is hermetic under root and rootless CI.
			name: "only missing namespace isolation",
			caps: HostCapabilities{
				HasSeccomp: true, HasLandlock: true, HasMountNS: false, HasUserNS: false,
				Details: "simulated-no-namespace",
			},
			allowDegraded:  true,
			enforceSeccomp: true,
			enforceLand:    true,
			wantBypassed:   []string{"namespace-isolation"},
			forbidBypassed: []string{"seccomp-bpf", "landlock-lsm"},
		},
		{
			name: "seccomp not enforced is not reported",
			caps: HostCapabilities{
				HasSeccomp: false, HasLandlock: true, HasMountNS: true, HasUserNS: true,
				Details: "simulated-no-seccomp-unenforced",
			},
			allowDegraded:  true,
			enforceSeccomp: false,
			enforceLand:    true,
			forbidBypassed: []string{"seccomp-bpf", "landlock-lsm", "namespace-isolation"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caps := tc.caps
			ResetHostCapabilitiesForTest(&caps)
			t.Cleanup(func() { ResetHostCapabilitiesForTest(nil) })

			rep, err := CheckSecurity(tc.allowDegraded, tc.enforceSeccomp, tc.enforceLand)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected fail-closed error, got report: %+v", rep)
				}
				if !strings.Contains(err.Error(), "fail-closed") {
					t.Errorf("expected 'fail-closed' in error, got %v", err)
				}
				if !strings.Contains(err.Error(), "--insecure-allow-degraded") {
					t.Errorf("expected bypass hint in error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error with allowDegraded=true: %v", err)
			}
			// The non-degraded branch must claim only the REQUIRED baselines:
			// with an enforcement layer disabled (enforceSeccomp/enforceLandlock
			// = false) that layer was never checked, so "all baselines
			// satisfied" would overstate the guarantee.
			if len(tc.wantBypassed) == 0 &&
				!strings.Contains(rep.Details, "all required host security baselines satisfied") {
				t.Errorf("expected Details to state required baselines satisfied, got %q", rep.Details)
			}
			if len(tc.wantBypassed) > 0 && !rep.Degraded {
				t.Errorf("expected report.Degraded to be true, bypassed=%v", rep.BypassedLayers)
			}
			if len(tc.wantBypassed) == 0 && rep.Degraded {
				t.Errorf("expected no bypassed layers, got %v", rep.BypassedLayers)
			}
			for _, want := range tc.wantBypassed {
				if !contains(rep.BypassedLayers, want) {
					t.Errorf("expected %q in bypassed layers, got %v", want, rep.BypassedLayers)
				}
			}
			for _, forbid := range tc.forbidBypassed {
				if contains(rep.BypassedLayers, forbid) {
					t.Errorf("did not expect %q in bypassed layers, got %v", forbid, rep.BypassedLayers)
				}
			}
		})
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

// GrantMonitorRW must bridge the DAC gap for a foreign-owned image and
// Cleanup must restore the original owner/mode. Requires root (chown).
func TestGrantMonitorRW_RestoresOnCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown requires root")
	}
	img := filepath.Join(t.TempDir(), "rootfs.img")
	if err := os.WriteFile(img, []byte("img"), 0o444); err != nil {
		t.Fatal(err)
	}
	env := &JailEnvironment{}
	const base = 165536
	if err := env.GrantMonitorRW(img, base, base); err != nil {
		t.Fatalf("grant: %v", err)
	}
	st, err := os.Stat(img)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Sys().(*syscall.Stat_t).Uid; got != base {
		t.Fatalf("owner = %d, want %d", got, base)
	}
	if st.Mode().Perm()&0o200 == 0 {
		t.Fatal("owner-write bit not added")
	}
	if err := env.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	st, err = os.Stat(img)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Sys().(*syscall.Stat_t).Uid; got != 0 {
		t.Fatalf("owner not restored: %d", got)
	}
	if st.Mode().Perm() != 0o444 {
		t.Fatalf("mode not restored: %o", st.Mode().Perm())
	}
}
