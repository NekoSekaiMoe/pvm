package volume

// hostmount_test.go — explicit host-directory mounts: whitelist gating,
// symlink escape refusal, plugin-result re-validation.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newTestManager(t *testing.T, prefixes []string) *Manager {
	t.Helper()
	m := NewManager(t.TempDir())
	m.SetHostMountPrefixes(prefixes)
	m.MustRegister(context.Background(), PluginConfig{Name: "builtin", Type: PluginTypeBuiltin}, NewBuiltin("builtin"))
	return m
}

func TestParseHostMountPrefixes(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   []string
		errSub string // "" means ok
	}{
		{"comma, newline and comment separated", "/a/b, /c\n# comment\n/d/e", []string{"/a/b", "/c", "/d/e"}, ""},
		{"relative prefix is an error", "relative/path", nil, "relative"},
		{"empty value means no prefixes", "", []string{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHostMountPrefixes(tc.in)
			if tc.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("ParseHostMountPrefixes(%q) err = %v, want containing %q", tc.in, err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("prefixes = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("prefix[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestExplicitHostMountWhitelistGating(t *testing.T) {
	shared := t.TempDir() // stands in for /srv/shared
	dataset := filepath.Join(shared, "dataset")
	if err := os.MkdirAll(dataset, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	attach := func(m *Manager, vol, hostPath string) (*AttachResult, error) {
		return m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: vol, Driver: "builtin", HostPath: hostPath})
	}

	t.Run("no whitelist refuses outright", func(t *testing.T) {
		m := newTestManager(t, nil)
		_, err := attach(m, "vol1", dataset)
		if err == nil || !strings.Contains(err.Error(), "PVM_HOST_MOUNT_PREFIXES") {
			t.Fatalf("no-whitelist attach must fail closed, got %v", err)
		}
	})

	t.Run("whitelisted prefix attaches exactly", func(t *testing.T) {
		m := newTestManager(t, []string{shared})
		res, err := attach(m, "vol2", dataset)
		if err != nil {
			t.Fatalf("whitelisted attach failed: %v", err)
		}
		if res.HostPath != dataset {
			t.Fatalf("host path = %q, want %q", res.HostPath, dataset)
		}
	})

	t.Run("outside the whitelist is refused without refcount", func(t *testing.T) {
		m := newTestManager(t, []string{shared})
		_, err := attach(m, "vol3", outside)
		if err == nil || !strings.Contains(err.Error(), "whitelist") {
			t.Fatalf("outside-whitelist attach must fail, got %v", err)
		}
		if n := m.RefCount("vol3"); n != 0 {
			t.Fatalf("rejected attach must not leave a refcount, got %d", n)
		}
	})

	t.Run("nonexistent directory is refused", func(t *testing.T) {
		m := newTestManager(t, []string{shared})
		_, err := attach(m, "vol4", filepath.Join(shared, "missing"))
		if err == nil || !strings.Contains(err.Error(), "not accessible") {
			t.Fatalf("missing dir must fail, got %v", err)
		}
	})

	t.Run("root prefix refused by validation", func(t *testing.T) {
		if _, err := validateExplicitHostPath(dataset, []string{"/"}); err == nil {
			t.Fatal("root whitelist prefix must be refused")
		}
	})

	t.Run("validated return is the resolved mount target", func(t *testing.T) {
		resolved, err := validateExplicitHostPath(dataset, []string{shared})
		if err != nil {
			t.Fatalf("whitelisted path must validate: %v", err)
		}
		if resolved != dataset {
			t.Fatalf("resolved mount target = %q, want the unsymlinked %q", resolved, dataset)
		}
	})
}

func TestExplicitHostMountSymlinkEscape(t *testing.T) {
	shared := t.TempDir()
	outside := t.TempDir()
	// A symlink INSIDE the whitelist pointing OUTSIDE it.
	link := filepath.Join(shared, "sneaky")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}
	m := newTestManager(t, []string{shared})
	_, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "v", Driver: "builtin", HostPath: link})
	if err == nil || !strings.Contains(err.Error(), "whitelist") {
		t.Fatalf("symlink escape must be refused, got %v", err)
	}
}

func TestExplicitHostMountPluginResultMismatch(t *testing.T) {
	shared := t.TempDir()
	// A lying plugin that returns a different path than requested. The
	// driver gate rejects it up front (only the builtin host-directory
	// plugin may serve explicit mounts); the echo-check deeper in Attach
	// remains as defense in depth for future builtin-typed drivers.
	m := newTestManager(t, []string{shared})
	m.MustRegister(context.Background(), PluginConfig{Name: "liar", Type: PluginTypeBuiltin}, &lyingPlugin{name: "liar"})

	_, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "v", Driver: "liar", HostPath: shared})
	if err == nil || !strings.Contains(err.Error(), "builtin host-directory driver") {
		t.Fatalf("non-builtin plugin serving an explicit mount must fail, got %v", err)
	}
}

type lyingPlugin struct{ name string }

func (p *lyingPlugin) Name() string           { return p.name }
func (p *lyingPlugin) PluginType() PluginType { return PluginTypeBuiltin }
func (p *lyingPlugin) Init(_ context.Context, _ PluginConfig) error {
	return nil
}
func (p *lyingPlugin) Attach(_ context.Context, req *AttachRequest) (*AttachResult, error) {
	return &AttachResult{VolumeID: req.VolumeID, HostPath: "/elsewhere/entirely"}, nil
}
func (p *lyingPlugin) Detach(_ context.Context, _ *DetachRequest) error { return nil }
func (p *lyingPlugin) Close() error                                     { return nil }

// compensationSpyPlugin returns a valid base-dir path for its first
// (lieFrom-1) attaches and an escaping path afterwards, recording every
// Detach's NodeRefLastDetach.
type compensationSpyPlugin struct {
	name     string
	lieFrom  int
	mu       sync.Mutex
	attaches int
	detaches []bool
}

func (p *compensationSpyPlugin) Name() string           { return p.name }
func (p *compensationSpyPlugin) PluginType() PluginType { return PluginTypeRPC }
func (p *compensationSpyPlugin) Init(_ context.Context, _ PluginConfig) error {
	return nil
}
func (p *compensationSpyPlugin) Attach(_ context.Context, req *AttachRequest) (*AttachResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attaches++
	if p.attaches < p.lieFrom {
		return &AttachResult{VolumeID: req.VolumeID,
			HostPath: filepath.Join(req.VolumeBaseDir, req.VolumeID)}, nil
	}
	return &AttachResult{VolumeID: req.VolumeID, HostPath: "/elsewhere"}, nil
}
func (p *compensationSpyPlugin) Detach(_ context.Context, req *DetachRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.detaches = append(p.detaches, req.NodeRefLastDetach)
	return nil
}
func (p *compensationSpyPlugin) Close() error { return nil }

// The compensation detach after a failed post-attach validation must be a
// LAST-reference detach only when THIS call created the node mount: a
// failed second attach still has live holders, and unmounting under them
// would tear down a volume someone else is using.
func TestAttachCompensationKeepsLiveHolders(t *testing.T) {
	t.Run("failed second attach does not last-detach", func(t *testing.T) {
		m := newTestManager(t, nil)
		p := &compensationSpyPlugin{name: "rec", lieFrom: 2}
		m.MustRegister(context.Background(), PluginConfig{Name: "rec", Type: PluginTypeRPC}, p)

		if _, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "v1", Driver: "rec"}); err != nil {
			t.Fatal(err)
		}
		// Second attach's result escapes the base dir: rejected, rolled
		// back — but the first holder's mount must survive.
		if _, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "v1", Driver: "rec"}); err == nil {
			t.Fatal("escaping second attach must fail")
		}
		if n := m.RefCount("v1"); n != 1 {
			t.Fatalf("refcount after failed second attach = %d, want 1", n)
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.detaches) != 1 || p.detaches[0] {
			t.Fatalf("compensation must be one NON-last detach, got %v", p.detaches)
		}
	})

	t.Run("failed first attach compensates with a last detach", func(t *testing.T) {
		m := newTestManager(t, nil)
		p := &compensationSpyPlugin{name: "rec2", lieFrom: 1}
		m.MustRegister(context.Background(), PluginConfig{Name: "rec2", Type: PluginTypeRPC}, p)
		if _, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "v9", Driver: "rec2"}); err == nil {
			t.Fatal("escaping first attach must fail")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		// The lying first attach is rejected by the containment rule; the
		// compensation is a last-reference detach (0→1 rolled back to 0).
		if len(p.detaches) != 1 || !p.detaches[0] {
			t.Fatalf("first-attach compensation must be a LAST detach, got %v", p.detaches)
		}
	})
}
