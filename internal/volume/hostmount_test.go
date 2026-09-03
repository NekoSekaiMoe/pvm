package volume

// hostmount_test.go — explicit host-directory mounts: whitelist gating,
// symlink escape refusal, plugin-result re-validation.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
	got, err := ParseHostMountPrefixes("/a/b, /c\n# comment\n/d/e")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/a/b", "/c", "/d/e"}
	if len(got) != len(want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("prefix[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := ParseHostMountPrefixes("relative/path"); err == nil {
		t.Fatal("relative prefix must be an error")
	}
	if got, _ := ParseHostMountPrefixes(""); len(got) != 0 {
		t.Fatal("empty value = no prefixes")
	}
}

func TestExplicitHostMountWhitelistGating(t *testing.T) {
	shared := t.TempDir() // stands in for /srv/shared
	dataset := filepath.Join(shared, "dataset")
	if err := os.MkdirAll(dataset, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	// 1. No whitelist configured: explicit mounts refused outright.
	m := newTestManager(t, nil)
	_, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "vol1", Driver: "builtin", HostPath: dataset})
	if err == nil || !strings.Contains(err.Error(), "PVM_HOST_MOUNT_PREFIXES") {
		t.Fatalf("no-whitelist attach must fail closed, got %v", err)
	}

	// 2. Whitelisted prefix: attach succeeds with the exact path.
	m = newTestManager(t, []string{shared})
	res, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "vol2", Driver: "builtin", HostPath: dataset})
	if err != nil {
		t.Fatalf("whitelisted attach failed: %v", err)
	}
	if res.HostPath != dataset {
		t.Fatalf("host path = %q, want %q", res.HostPath, dataset)
	}

	// 3. Outside the whitelist: refused, refcount untouched.
	m = newTestManager(t, []string{shared})
	_, err = m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "vol3", Driver: "builtin", HostPath: outside})
	if err == nil || !strings.Contains(err.Error(), "whitelist") {
		t.Fatalf("outside-whitelist attach must fail, got %v", err)
	}
	if n := m.RefCount("vol3"); n != 0 {
		t.Fatalf("rejected attach must not leave a refcount, got %d", n)
	}

	// 4. Nonexistent directory: refused (must pre-exist).
	m = newTestManager(t, []string{shared})
	_, err = m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "vol4", Driver: "builtin", HostPath: filepath.Join(shared, "missing")})
	if err == nil || !strings.Contains(err.Error(), "not accessible") {
		t.Fatalf("missing dir must fail, got %v", err)
	}

	// 5. Root prefix refused by validation.
	if _, err := validateExplicitHostPath(dataset, []string{"/"}); err == nil {
		t.Fatal("root whitelist prefix must be refused")
	}
	// 6. The validated return value is the symlink-resolved mount target.
	resolved, err := validateExplicitHostPath(dataset, []string{shared})
	if err != nil {
		t.Fatalf("whitelisted path must validate: %v", err)
	}
	if resolved != dataset {
		t.Fatalf("resolved mount target = %q, want the unsymlinked %q", resolved, dataset)
	}
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
	// A lying plugin that returns a different path than requested.
	m := newTestManager(t, []string{shared})
	m.MustRegister(context.Background(), PluginConfig{Name: "liar", Type: PluginTypeBuiltin}, &lyingPlugin{name: "liar"})

	_, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "v", Driver: "liar", HostPath: shared})
	if err == nil || !strings.Contains(err.Error(), "instead of the requested") {
		t.Fatalf("plugin swapping the host path must fail, got %v", err)
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
