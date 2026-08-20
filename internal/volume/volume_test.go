package volume

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinAttach_Detach_RefCount(t *testing.T) {
	base := t.TempDir()
	m := NewManager(base)
	ctx := context.Background()
	if err := m.Register(ctx, PluginConfig{Name: "demo", Type: PluginTypeBuiltin}, NewBuiltin("demo")); err != nil {
		t.Fatalf("register: %v", err)
	}

	// first attach -> mkdir
	r1, err := m.Attach(ctx, &AttachRequest{SandboxID: "sb-1", VolumeID: "vol-1", Driver: "demo"})
	if err != nil {
		t.Fatalf("attach 1: %v", err)
	}
	if r1.HostPath == "" {
		t.Fatalf("empty HostPath")
	}
	if _, err := os.Stat(r1.HostPath); err != nil {
		t.Fatalf("hostPath not created: %v", err)
	}
	if got := m.RefCount("vol-1"); got != 1 {
		t.Fatalf("refCount after 1st attach = %d, want 1", got)
	}

	// second sandbox reuses same hostPath (refCount 1→2)
	r2, err := m.Attach(ctx, &AttachRequest{SandboxID: "sb-2", VolumeID: "vol-1", Driver: "demo"})
	if err != nil {
		t.Fatalf("attach 2: %v", err)
	}
	if r2.HostPath != r1.HostPath {
		t.Fatalf("HostPath mismatch: %q vs %q", r2.HostPath, r1.HostPath)
	}
	if got := m.RefCount("vol-1"); got != 2 {
		t.Fatalf("refCount after 2nd attach = %d, want 2", got)
	}

	// first detach -> post 1, not last
	if err := m.Detach(ctx, &DetachRequest{SandboxID: "sb-1", VolumeID: "vol-1", Driver: "demo"}); err != nil {
		t.Fatalf("detach 1: %v", err)
	}
	if got := m.RefCount("vol-1"); got != 1 {
		t.Fatalf("refCount after 1st detach = %d, want 1", got)
	}
	if _, err := os.Stat(r1.HostPath); err != nil {
		t.Fatalf("hostPath should still exist after non-last detach: %v", err)
	}

	// last detach -> post 0
	if err := m.Detach(ctx, &DetachRequest{SandboxID: "sb-2", VolumeID: "vol-1", Driver: "demo"}); err != nil {
		t.Fatalf("detach 2: %v", err)
	}
	if got := m.RefCount("vol-1"); got != 0 {
		t.Fatalf("refCount after last detach = %d, want 0", got)
	}
}

func TestManager_HostPathContainment(t *testing.T) {
	base := t.TempDir()
	m := NewManager(base)
	ctx := context.Background()

	// A rogue plugin returning a path outside baseDir must be rejected.
	rogue := &roguePlugin{hostPath: "/tmp/evil"}
	if err := m.Register(ctx, PluginConfig{Name: "rogue", Type: PluginTypeBuiltin}, rogue); err != nil {
		t.Fatalf("register rogue: %v", err)
	}
	_, err := m.Attach(ctx, &AttachRequest{SandboxID: "sb-1", VolumeID: "vol-x", Driver: "rogue"})
	if err == nil {
		t.Fatalf("expected containment error, got nil")
	}
	// valid path under baseDir is OK (reuse builtin to prove)
	m2 := NewManager(base)
	if err := m2.Register(ctx, PluginConfig{Name: "ok", Type: PluginTypeBuiltin}, NewBuiltin("ok")); err != nil {
		t.Fatalf("register ok: %v", err)
	}
	// HostPath == <base>/ok-vol-y is inside baseDir, so no error
	res, err := m2.Attach(ctx, &AttachRequest{SandboxID: "sb-1", VolumeID: "vol-y", Driver: "ok"})
	if err != nil {
		t.Fatalf("valid attach: %v", err)
	}
	if !filepath.HasPrefix(filepath.Clean(res.HostPath), filepath.Clean(base)) {
		t.Fatalf("HostPath not under baseDir: %q", res.HostPath)
	}
}

func TestManager_DuplicateDriver(t *testing.T) {
	m := NewManager(t.TempDir())
	ctx := context.Background()
	if err := m.Register(ctx, PluginConfig{Name: "dup", Type: PluginTypeBuiltin}, NewBuiltin("dup")); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := m.Register(ctx, PluginConfig{Name: "dup", Type: PluginTypeBuiltin}, NewBuiltin("dup")); err == nil {
		t.Fatalf("expected duplicate driver error")
	}
}

func TestManager_UnknownDriver(t *testing.T) {
	m := NewManager(t.TempDir())
	_, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "v", Driver: "nope"})
	if err == nil {
		t.Fatalf("expected unknown driver error")
	}
}

type roguePlugin struct {
	hostPath string
}

func (r *roguePlugin) Name() string            { return "rogue" }
func (r *roguePlugin) PluginType() PluginType { return PluginTypeBuiltin }
func (r *roguePlugin) Init(_ context.Context, _ PluginConfig) error { return nil }
func (r *roguePlugin) Attach(_ context.Context, req *AttachRequest) (*AttachResult, error) {
	return &AttachResult{VolumeID: req.VolumeID, HostPath: r.hostPath}, nil
}
func (r *roguePlugin) Detach(_ context.Context, _ *DetachRequest) error { return nil }
func (r *roguePlugin) Close() error                                      { return nil }
