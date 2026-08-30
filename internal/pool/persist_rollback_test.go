package pool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// brokenPersistPath returns a path whose base name exceeds NAME_MAX: reads
// report ENOENT (a legal-but-absent file) while fsjson's temp-file pattern
// always fails to create — deterministic and root-safe persist-failure
// injection, shared with TestEnablePersistenceSnapshotFailureFallsBackToMemory.
func brokenPersistPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), strings.Repeat("s", 250))
}

// breakPersist swaps the live store path for an unwritable one (same
// package; tests here are single-goroutine).
func breakPersist(m *Manager, t *testing.T) {
	t.Helper()
	m.mu.Lock()
	m.persistPath = brokenPersistPath(t)
	m.mu.Unlock()
}

func enableGoodStore(t *testing.T, m *Manager) string {
	t.Helper()
	good := filepath.Join(t.TempDir(), "pool.json")
	if err := m.EnablePersistence(good); err != nil {
		t.Fatalf("EnablePersistence: %v", err)
	}
	return good
}

// TestSetQuotaRollsBackWhenPersistFails: a quota change that cannot be
// persisted must fail AND roll the in-memory quota back to the last
// persisted value — otherwise memory runs ahead of the store and a restart
// silently resurrects the old quota.
func TestSetQuotaRollsBackWhenPersistFails(t *testing.T) {
	m := NewManager(4, nil)
	good := enableGoodStore(t, m)
	if err := m.SetQuota("t", Quota{MaxConcurrent: 5}); err != nil {
		t.Fatalf("SetQuota on a healthy store: %v", err)
	}

	breakPersist(m, t)
	if err := m.SetQuota("t", Quota{MaxConcurrent: 9}); err == nil {
		t.Fatal("SetQuota must fail when the change cannot be persisted")
	}
	if q := m.quotas["t"]; q.MaxConcurrent != 5 {
		t.Fatalf("in-memory quota = %+v, want MaxConcurrent rolled back to 5", q)
	}
	// A first-ever quota must also vanish, not linger un-persisted.
	if err := m.SetQuota("fresh", DefaultQuota()); err == nil {
		t.Fatal("SetQuota on a new tenant must fail when persist fails")
	}
	if _, ok := m.quotas["fresh"]; ok {
		t.Fatal("failed new-quota install left an entry in memory")
	}

	// The store file itself was never touched by the failed changes.
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var pf poolFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		t.Fatalf("store corrupt after failed SetQuota: %v", err)
	}
	if got := pf.Quotas["t"].MaxConcurrent; got != 5 {
		t.Fatalf("store MaxConcurrent = %d, want 5", got)
	}
	if _, ok := pf.Quotas["fresh"]; ok {
		t.Fatal("store contains the tenant whose SetQuota failed")
	}
}

// TestWarmRollsBackWhenPersistFails: a warm sandbox that cannot be mirrored
// to the store must be dropped from the pool AND torn down — it exists
// externally (Factory built it) but would be lost on restart.
func TestWarmRollsBackWhenPersistFails(t *testing.T) {
	m := NewManager(4, nil)
	enableGoodStore(t, m)
	m.Factory = func(tmpl Template) (string, error) { return "sb-factory-1", nil }
	var destroyed []string
	m.Destroyer = func(id string) error {
		destroyed = append(destroyed, id)
		return nil
	}

	breakPersist(m, t)
	if n := m.Warm(Template{Name: "tpl"}, 1); n != 0 {
		t.Fatalf("Warm created = %d, want 0 when the persist fails", n)
	}
	if _, _, total := m.Stats(); total != 0 {
		t.Fatalf("pool total = %d, want 0 (append rolled back)", total)
	}
	if len(destroyed) != 1 || destroyed[0] != "sb-factory-1" {
		t.Fatalf("destroyer calls = %v, want exactly [sb-factory-1]", destroyed)
	}
}

func warmAndClaim(t *testing.T, m *Manager, tenant string) string {
	t.Helper()
	if err := m.SetQuota(tenant, DefaultQuota()); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	if n := m.Warm(Template{Name: "tpl", Memory: "512M", CPU: 1}, 1); n != 1 {
		t.Fatalf("Warm = %d, want 1", n)
	}
	id, err := m.Claim(tenant, Template{Name: "tpl", Memory: "512M", CPU: 1}, "task-1")
	if err != nil {
		t.Fatalf("Claim on healthy store: %v", err)
	}
	return id
}

// TestClaimWarmRollsBackWhenPersistFails: when a warm claim cannot be
// persisted the sandbox must return to ready and the quota counters must be
// undone (including the hourly start entry).
func TestClaimWarmRollsBackWhenPersistFails(t *testing.T) {
	m := NewManager(4, nil)
	enableGoodStore(t, m)
	if err := m.SetQuota("t", DefaultQuota()); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	if n := m.Warm(Template{Name: "tpl", Memory: "512M", CPU: 1}, 1); n != 1 {
		t.Fatalf("Warm = %d, want 1", n)
	}

	breakPersist(m, t)
	if _, err := m.Claim("t", Template{Name: "tpl", Memory: "512M", CPU: 1}, "task-2"); err == nil {
		t.Fatal("Claim must fail when the claim cannot be persisted")
	}
	ready, claimed, _ := m.Stats()
	if ready != 1 || claimed != 0 {
		t.Fatalf("ready=%d claimed=%d, want 1/0 (claim rolled back)", ready, claimed)
	}
	m.mu.Lock()
	running, hourlyN := m.running["t"], len(m.hourly["t"])
	m.mu.Unlock()
	if running != 0 {
		t.Fatalf("running counter = %d, want 0 after rollback", running)
	}
	if hourlyN != 0 {
		t.Fatalf("hourly entries = %d, want 0 (failed claim's entry rolled back)", hourlyN)
	}
}

// TestClaimOnDemandRollsBackWhenPersistFails: an on-demand claim that cannot
// be persisted must pop the entry, undo the counters and destroy the
// Factory-created sandbox.
func TestClaimOnDemandRollsBackWhenPersistFails(t *testing.T) {
	m := NewManager(4, nil)
	enableGoodStore(t, m)
	if err := m.SetQuota("t", DefaultQuota()); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	m.Factory = func(tmpl Template) (string, error) { return "sb-ondemand-1", nil }
	var destroyed []string
	m.Destroyer = func(id string) error {
		destroyed = append(destroyed, id)
		return nil
	}

	breakPersist(m, t)
	if _, err := m.Claim("t", Template{Name: "tpl", Memory: "512M", CPU: 1}, "task-1"); err == nil {
		t.Fatal("Claim must fail when the claim cannot be persisted")
	}
	if _, _, total := m.Stats(); total != 0 {
		t.Fatalf("pool total = %d, want 0 (on-demand append rolled back)", total)
	}
	if len(destroyed) != 1 || destroyed[0] != "sb-ondemand-1" {
		t.Fatalf("destroyer calls = %v, want exactly [sb-ondemand-1]", destroyed)
	}
}

// TestReleaseRecycleRollsBackWhenPersistFails: a recycle whose persist fails
// must restore the claimed state and the counters the release had taken.
func TestReleaseRecycleRollsBackWhenPersistFails(t *testing.T) {
	m := NewManager(4, nil)
	good := enableGoodStore(t, m)
	id := warmAndClaim(t, m, "t")

	breakPersist(m, t)
	if err := m.Release(id, true); err == nil {
		t.Fatal("Release(recycle) must fail when the persist fails")
	}
	ready, claimed, _ := m.Stats()
	if ready != 0 || claimed != 1 {
		t.Fatalf("ready=%d claimed=%d, want 0/1 (recycle rolled back)", ready, claimed)
	}
	m.mu.Lock()
	running := m.running["t"]
	m.mu.Unlock()
	if running != 1 {
		t.Fatalf("running counter = %d, want 1 after rollback", running)
	}
	// The store never saw the recycle.
	raw, _ := os.ReadFile(good)
	var pf poolFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		t.Fatalf("store corrupt: %v", err)
	}
	for _, s := range pf.Pool {
		if s.ID == id && s.State != SandboxClaimed {
			t.Fatalf("store state for %s = %s, want claimed", id, s.State)
		}
	}
}

// TestReleaseDestroyRollsBackWhenPersistFails: when the removal cannot be
// persisted the sandbox must be re-inserted and the destroyer must NOT run
// for a sandbox the store still lists.
func TestReleaseDestroyRollsBackWhenPersistFails(t *testing.T) {
	m := NewManager(4, nil)
	enableGoodStore(t, m)
	id := warmAndClaim(t, m, "t")
	var destroyed []string
	m.Destroyer = func(id string) error {
		destroyed = append(destroyed, id)
		return nil
	}

	breakPersist(m, t)
	if err := m.Release(id, false); err == nil {
		t.Fatal("Release(destroy) must fail when the persist fails")
	}
	_, claimed, total := m.Stats()
	if total != 1 || claimed != 1 {
		t.Fatalf("total=%d claimed=%d, want 1/1 (removal rolled back)", total, claimed)
	}
	if len(destroyed) != 0 {
		t.Fatalf("destroyer ran for a sandbox the store still owns: %v", destroyed)
	}
}

// TestEnablePersistenceReadErrorClearsGuard: a store path that cannot be
// read (EISDIR here; EACCES in production) must fail EnablePersistence AND
// leave no poisoned persistPath — the idempotency guard would otherwise
// reject every later EnablePersistence, including valid ones.
func TestEnablePersistenceReadErrorClearsGuard(t *testing.T) {
	m := NewManager(4, nil)
	if err := m.EnablePersistence(t.TempDir()); err == nil {
		t.Fatal("EnablePersistence must fail when the store path cannot be read")
	}
	m.mu.Lock()
	poisoned := m.persistPath
	m.mu.Unlock()
	if poisoned != "" {
		t.Fatalf("persistPath = %q after read failure, want cleared", poisoned)
	}
	enableGoodStore(t, m) // must not be rejected by the guard
}

// TestPersistSnapshotRestore pins the atomic-rollback helpers used when the
// initial persist of EnablePersistence fails: restoreLocked must recover the
// exact pre-restore pool, quotas, capacity and live counters, so a retry on
// the same path cannot duplicate restored sandboxes or double counts.
func TestPersistSnapshotRestore(t *testing.T) {
	m := NewManager(4, nil)
	m.pool = append(m.pool, &Sandbox{ID: "a"}, &Sandbox{ID: "b"})
	m.quotas["t"] = Quota{MaxConcurrent: 3}
	m.running["t"] = 2
	m.cpu["t"] = 4
	m.memMB["t"] = 1024
	t0 := time.Now()
	m.hourly["t"] = []time.Time{t0}

	snap := m.snapshotLocked()
	// Simulate what a restore + failed persist would leave behind.
	m.pool = append(m.pool, &Sandbox{ID: "c"}, &Sandbox{ID: "d"})
	m.quotas["t"] = Quota{MaxConcurrent: 9}
	m.quotas["other"] = DefaultQuota()
	m.running["t"] = 7
	m.cpu["t"] = 21
	m.memMB["t"] = 4096
	m.hourly["t"] = append(m.hourly["t"], t0.Add(time.Second), t0.Add(2*time.Second))

	m.restoreLocked(snap)
	if len(m.pool) != 2 || m.pool[0].ID != "a" || m.pool[1].ID != "b" {
		t.Fatalf("pool after restore = %v, want [a b]", m.pool)
	}
	if m.quotas["t"].MaxConcurrent != 3 {
		t.Fatalf("quota after restore = %+v", m.quotas["t"])
	}
	if _, ok := m.quotas["other"]; ok {
		t.Fatal("restored quotas kept a key added after the snapshot")
	}
	if m.running["t"] != 2 || m.cpu["t"] != 4 || m.memMB["t"] != 1024 {
		t.Fatalf("counters after restore = running %d cpu %d mem %d, want 2/4/1024", m.running["t"], m.cpu["t"], m.memMB["t"])
	}
	if len(m.hourly["t"]) != 1 || !m.hourly["t"][0].Equal(t0) {
		t.Fatalf("hourly after restore = %v, want [%v]", m.hourly["t"], t0)
	}
}
