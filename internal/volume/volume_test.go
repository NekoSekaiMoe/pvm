package volume

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	var first *AttachResult
	attach := func(sb string) *AttachResult {
		r, err := m.Attach(ctx, &AttachRequest{SandboxID: sb, VolumeID: "vol-1", Driver: "demo"})
		if err != nil {
			t.Fatalf("attach %s: %v", sb, err)
		}
		return r
	}
	detach := func(sb string) {
		if err := m.Detach(ctx, &DetachRequest{SandboxID: sb, VolumeID: "vol-1", Driver: "demo"}); err != nil {
			t.Fatalf("detach %s: %v", sb, err)
		}
	}

	steps := []struct {
		name       string
		op         func()
		wantRefCnt int64
		hostExists bool // whether the first attach's host path must exist after the op
	}{
		{"first attach creates host path", func() { first = attach("sb-1") }, 1, true},
		{"second sandbox reuses host path", func() {
			if got := attach("sb-2"); got.HostPath != first.HostPath {
				t.Fatalf("HostPath mismatch: %q vs %q", got.HostPath, first.HostPath)
			}
		}, 2, true},
		{"non-last detach keeps host path", func() { detach("sb-1") }, 1, true},
		{"last detach drops bookkeeping", func() { detach("sb-2") }, 0, true},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			st.op()
			if got := m.RefCount("vol-1"); got != st.wantRefCnt {
				t.Fatalf("refCount = %d, want %d", got, st.wantRefCnt)
			}
			_, err := os.Stat(first.HostPath)
			if st.hostExists && err != nil {
				t.Fatalf("hostPath %q: %v", first.HostPath, err)
			}
		})
	}
}

func TestManager_HostPathContainment(t *testing.T) {
	base := t.TempDir()
	m := NewManager(base)
	ctx := context.Background()

	// Rogue plugins returning paths outside baseDir must be rejected. The
	// sibling-prefix case (base+"-evil") is the adversarial one: it shares
	// base's string prefix but is NOT inside base, so a naive
	// strings.HasPrefix(clean, base) check (or deprecated filepath.HasPrefix)
	// would wrongly accept it.
	rogues := []struct {
		name     string
		hostPath string
	}{
		{name: "rogue-abs", hostPath: "/tmp/evil"},
		{name: "rogue-sibling", hostPath: base + "-evil"},
	}
	for _, rg := range rogues {
		if err := m.Register(ctx, PluginConfig{Name: rg.name, Type: PluginTypeBuiltin}, &roguePlugin{hostPath: rg.hostPath}); err != nil {
			t.Fatalf("register %s: %v", rg.name, err)
		}
	}
	for _, rg := range rogues {
		t.Run(rg.name, func(t *testing.T) {
			_, err := m.Attach(ctx, &AttachRequest{SandboxID: "sb-1", VolumeID: "vol-x", Driver: rg.name})
			if err == nil {
				t.Fatalf("expected containment error for HostPath %q, got nil", rg.hostPath)
			}
		})
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
		// negative refcount must be rejected before persisting
		if err := s.Create(VolumeRecord{VolumeID: "vol-neg", Driver: "builtin", RefCount: -1}); err == nil {
			t.Fatalf("expected error for negative refcount")
		} else if !errors.Is(err, ErrInvalid) {
			t.Fatalf("negative refcount error = %v, want ErrInvalid", err)
		}
		if _, err := s.Get("vol-neg"); err == nil {
			t.Fatalf("negative-refcount record must not be persisted")
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
		if !errors.Is(err, ErrStillMounted) {
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

// TestManager_ConcurrentAttachDetach drives concurrent Attach and Detach for
// the same volume: the per-volume lifecycle serialization must keep the
// refcount exact (no lost decrements, no duplicate teardown of the last
// detach) and the final count must return to 0.
func TestManager_ConcurrentAttachDetach(t *testing.T) {
	base := t.TempDir()
	m := NewManager(base)
	ctx := context.Background()
	if err := m.Register(ctx, PluginConfig{Name: "demo", Type: PluginTypeBuiltin}, NewBuiltin("demo")); err != nil {
		t.Fatalf("register: %v", err)
	}

	const n = 16
	// n attaches
	for i := 0; i < n; i++ {
		if _, err := m.Attach(ctx, &AttachRequest{SandboxID: fmt.Sprintf("sb-%d", i), VolumeID: "vol-race", Driver: "demo"}); err != nil {
			t.Fatalf("attach %d: %v", i, err)
		}
	}
	// concurrent detaches: all must succeed and drive the count exactly to 0
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := m.Detach(ctx, &DetachRequest{SandboxID: fmt.Sprintf("sb-%d", i), VolumeID: "vol-race", Driver: "demo"}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent detach: %v", err)
	}
	if got := m.RefCount("vol-race"); got != 0 {
		t.Fatalf("refcount after concurrent detaches = %d, want 0", got)
	}
	if m.HostPath("vol-race") != "" {
		t.Fatalf("attached state must be cleared at count 0")
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
