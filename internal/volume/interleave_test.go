package volume

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

// recordingPlugin records each Attach/Detach call's node-transition kind
// ("first"/"again", "last"/"again") in call order, and answers with a valid
// host path inside the manager's base dir.
type recordingPlugin struct {
	mu          sync.Mutex
	hostPath    string
	attachCalls []string
	detachCalls []string
}

func (r *recordingPlugin) Name() string           { return "rec" }
func (r *recordingPlugin) PluginType() PluginType { return PluginTypeBuiltin }
func (r *recordingPlugin) Init(_ context.Context, _ PluginConfig) error {
	return nil
}
func (r *recordingPlugin) Close() error { return nil }

func (r *recordingPlugin) Attach(_ context.Context, req *AttachRequest) (*AttachResult, error) {
	kind := "again"
	if req.NodeRefFirstAttach {
		kind = "first"
	}
	r.mu.Lock()
	r.attachCalls = append(r.attachCalls, kind)
	r.mu.Unlock()
	return &AttachResult{VolumeID: req.VolumeID, HostPath: r.hostPath}, nil
}

func (r *recordingPlugin) Detach(_ context.Context, req *DetachRequest) error {
	kind := "again"
	if req.NodeRefLastDetach {
		kind = "last"
	}
	r.mu.Lock()
	r.detachCalls = append(r.detachCalls, kind)
	r.mu.Unlock()
	return nil
}

func (r *recordingPlugin) snapshot() (attaches, detaches []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.attachCalls...), append([]string{}, r.detachCalls...)
}

// TestManager_AttachOrderMatchesReservationOrder is the regression test for
// the reservation-order race: when the refcount was reserved before taking
// the per-volume lock, two concurrent Attaches could reserve counts 0 and 1
// in one order while their plugin calls ran in the other — the plugin then
// saw the FIRST attach as a re-attach (or vice versa). Reserving under the
// volume lock makes the plugin call order match the reservation order, so
// the first plugin call always observes NodeRefFirstAttach=true.
func TestManager_AttachOrderMatchesReservationOrder(t *testing.T) {
	base := t.TempDir()
	m := NewManager(base)
	rec := &recordingPlugin{hostPath: filepath.Join(base, "rec-vol")}
	if err := m.Register(context.Background(), PluginConfig{Name: "rec", Type: PluginTypeBuiltin}, rec); err != nil {
		t.Fatalf("register: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := m.Attach(context.Background(), &AttachRequest{
				SandboxID: "sbx", Namespace: "ns", VolumeID: "vol-order", Driver: "rec",
			}); err != nil {
				t.Errorf("attach %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	attaches, _ := rec.snapshot()
	want := []string{"first", "again"}
	if len(attaches) != 2 || attaches[0] != want[0] || attaches[1] != want[1] {
		t.Fatalf("plugin call order %v does not match reservation order %v", attaches, want)
	}
	if got := m.RefCount("vol-order"); got != 2 {
		t.Fatalf("refcount = %d, want 2", got)
	}
}

// TestManager_DetachOrderMatchesReservationOrder: same invariant on the
// detach side — the plugin call that observes NodeRefLastDetach=true must be
// the LAST detach call, and the count/attached state must land exactly at
// zero (no lost teardown, no duplicate last-detach).
func TestManager_DetachOrderMatchesReservationOrder(t *testing.T) {
	base := t.TempDir()
	m := NewManager(base)
	rec := &recordingPlugin{hostPath: filepath.Join(base, "rec-vol")}
	if err := m.Register(context.Background(), PluginConfig{Name: "rec", Type: PluginTypeBuiltin}, rec); err != nil {
		t.Fatalf("register: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := m.Attach(ctx, &AttachRequest{
			SandboxID: "sbx", Namespace: "ns", VolumeID: "vol-det", Driver: "rec",
		}); err != nil {
			t.Fatalf("attach %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := m.Detach(ctx, &DetachRequest{
				SandboxID: "sbx", Namespace: "ns", VolumeID: "vol-det", Driver: "rec",
			}); err != nil {
				t.Errorf("detach %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	_, detaches := rec.snapshot()
	want := []string{"again", "last"}
	if len(detaches) != 2 || detaches[0] != want[0] || detaches[1] != want[1] {
		t.Fatalf("plugin call order %v does not match reservation order %v", detaches, want)
	}
	if got := m.RefCount("vol-det"); got != 0 {
		t.Fatalf("refcount = %d, want 0", got)
	}
	if m.HostPath("vol-det") != "" {
		t.Fatalf("attached state must be cleared at count 0")
	}
}
