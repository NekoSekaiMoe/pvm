package volume

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	// Mirror Manager.validateHostPath exactly: after cleaning both paths,
	// accept only an exact base match or a prefix followed by filepath.Separator.
	// (filepath.HasPrefix would wrongly accept sibling prefixes like /tmp/abc
	// for base /tmp/a.)
	clean := filepath.Clean(res.HostPath)
	baseClean := filepath.Clean(base)
	if clean != baseClean && !strings.HasPrefix(clean, baseClean+string(filepath.Separator)) {
		t.Fatalf("HostPath not under baseDir: %q (base %q)", res.HostPath, base)
	}
}

// TestManager_Errors collects Manager error paths as table-driven cases.
func TestManager_Errors(t *testing.T) {
	tests := []struct {
		name string
		op   func(t *testing.T, m *Manager) error
	}{
		{
			name: "duplicate driver",
			op: func(t *testing.T, m *Manager) error {
				ctx := context.Background()
				if err := m.Register(ctx, PluginConfig{Name: "dup", Type: PluginTypeBuiltin}, NewBuiltin("dup")); err != nil {
					t.Fatalf("first register: %v", err)
				}
				return m.Register(ctx, PluginConfig{Name: "dup", Type: PluginTypeBuiltin}, NewBuiltin("dup"))
			},
		},
		{
			name: "unknown driver",
			op: func(t *testing.T, m *Manager) error {
				_, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "v", Driver: "nope"})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManager(t.TempDir())
			if err := tt.op(t, m); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

// TestStore_Lifecycle walks the Store state machine (Create → Get → List →
// IncRef → Delete-blocked → DecRef → Delete) against an injected root.
func TestStore_Lifecycle(t *testing.T) {
	s := NewStore(t.TempDir())

	t.Run("create and get", func(t *testing.T) {
		if err := s.Create(VolumeRecord{VolumeID: "vol-a", Driver: "builtin"}); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := s.Get("vol-a")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.VolumeID != "vol-a" || got.Driver != "builtin" {
			t.Fatalf("record mismatch: %+v", got)
		}
		if got.CreatedAt.IsZero() {
			t.Fatalf("CreatedAt not defaulted")
		}
		// duplicate create must fail
		if err := s.Create(VolumeRecord{VolumeID: "vol-a"}); err == nil {
			t.Fatalf("expected duplicate-create error")
		}
	})

	t.Run("list", func(t *testing.T) {
		if err := s.Create(VolumeRecord{VolumeID: "vol-b", CreatedAt: time.Now().UTC().Add(time.Second)}); err != nil {
			t.Fatalf("create vol-b: %v", err)
		}
		list, err := s.List()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("list len = %d, want 2", len(list))
		}
		if list[0].VolumeID != "vol-a" || list[1].VolumeID != "vol-b" {
			t.Fatalf("list not sorted by CreatedAt: [%s %s]", list[0].VolumeID, list[1].VolumeID)
		}
	})

	t.Run("delete blocked while mounted", func(t *testing.T) {
		if err := s.IncRef("vol-a"); err != nil {
			t.Fatalf("incref: %v", err)
		}
		if err := s.IncRef("vol-a"); err != nil {
			t.Fatalf("incref 2: %v", err)
		}
		rec, _ := s.Get("vol-a")
		if rec.RefCount != 2 {
			t.Fatalf("refcount after 2 IncRef = %d, want 2", rec.RefCount)
		}
		err := s.Delete("vol-a")
		if err == nil {
			t.Fatalf("expected refcount-blocked delete error")
		}
		if !strings.Contains(err.Error(), "still mounted") {
			t.Fatalf("unexpected error: %v", err)
		}
		// volume still present after blocked delete
		if _, err := s.Get("vol-a"); err != nil {
			t.Fatalf("vol-a vanished after blocked delete: %v", err)
		}
	})

	t.Run("decref and delete", func(t *testing.T) {
		if err := s.DecRef("vol-a"); err != nil {
			t.Fatalf("decref: %v", err)
		}
		if err := s.DecRef("vol-a"); err != nil {
			t.Fatalf("decref 2: %v", err)
		}
		rec, _ := s.Get("vol-a")
		if rec.RefCount != 0 {
			t.Fatalf("refcount after 2 DecRef = %d, want 0", rec.RefCount)
		}
		if err := s.Delete("vol-a"); err != nil {
			t.Fatalf("delete after zero refcount: %v", err)
		}
		if _, err := s.Get("vol-a"); err == nil {
			t.Fatalf("expected not-found after delete")
		}
	})
}

// TestStore_InvalidID verifies the volumeDir ID validation (path-traversal
// defense) across all Store entry points.
func TestStore_InvalidID(t *testing.T) {
	s := NewStore(t.TempDir())
	invalid := []string{
		"",
		"a/b",
		"../escape",
		"..",
		"a.b",
		"a b",
		strings.Repeat("x", 129),
	}
	for _, id := range invalid {
		t.Run(fmt.Sprintf("id_%q", id), func(t *testing.T) {
			if err := s.Create(VolumeRecord{VolumeID: id}); err == nil {
				t.Fatalf("Create accepted invalid id")
			}
			if _, err := s.Get(id); err == nil {
				t.Fatalf("Get accepted invalid id")
			}
			if err := s.Delete(id); err == nil {
				t.Fatalf("Delete accepted invalid id")
			}
			if err := s.IncRef(id); err == nil {
				t.Fatalf("IncRef accepted invalid id")
			}
			if err := s.DecRef(id); err == nil {
				t.Fatalf("DecRef accepted invalid id")
			}
			if _, err := s.volumeDir(id); err == nil {
				t.Fatalf("volumeDir accepted invalid id")
			}
		})
	}
	// Nothing may have been written outside/inside the root.
	list, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("invalid ids created records: %+v", list)
	}
}

type roguePlugin struct {
	hostPath string
}

func (r *roguePlugin) Name() string                                 { return "rogue" }
func (r *roguePlugin) PluginType() PluginType                       { return PluginTypeBuiltin }
func (r *roguePlugin) Init(_ context.Context, _ PluginConfig) error { return nil }
func (r *roguePlugin) Attach(_ context.Context, req *AttachRequest) (*AttachResult, error) {
	return &AttachResult{VolumeID: req.VolumeID, HostPath: r.hostPath}, nil
}
func (r *roguePlugin) Detach(_ context.Context, _ *DetachRequest) error { return nil }
func (r *roguePlugin) Close() error                                     { return nil }
