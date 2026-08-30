package pool

import (
	"path/filepath"
	"testing"
)

func TestPoolPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "pool.json")

	m1 := NewManager(8, nil)
	if err := m1.EnablePersistence(store); err != nil {
		t.Fatal(err)
	}
	m1.Factory = func(t Template) (string, error) { return "sb-" + t.Name, nil }
	if got := m1.Warm(Template{Name: "tpl-a"}, 2); got != 2 {
		t.Fatalf("warm 2, got %d", got)
	}
	m1.SetQuota("tenant-x", Quota{MaxConcurrent: 3, MaxCPU: 4, MaxMemoryMB: 512, MaxTasksPerHour: 10})
	if _, err := m1.Claim("tenant-x", Template{Name: "tpl-a", Memory: "128M", CPU: 1}, "task-1"); err != nil {
		t.Fatal(err)
	}

	// Restart: a fresh manager loads the same store.
	m2 := NewManager(8, nil)
	if err := m2.EnablePersistence(store); err != nil {
		t.Fatal(err)
	}
	ready, claimed, total := m2.Stats()
	if total != 2 || claimed != 1 || ready != 1 {
		t.Fatalf("restored stats ready=%d claimed=%d total=%d", ready, claimed, total)
	}
	// Quota restored.
	if q, ok := m2.quotas["tenant-x"]; !ok || q.MaxConcurrent != 3 {
		t.Fatalf("quota must survive restart: %+v", q)
	}
	// Claimed quota counters rebuilt: tenant-x holds 1 running / 1 cpu.
	if m2.running["tenant-x"] != 1 || m2.cpu["tenant-x"] != 1 {
		t.Fatalf("live counters must be rebuilt: running=%d cpu=%d", m2.running["tenant-x"], m2.cpu["tenant-x"])
	}
	// Release after restart still finds and recycles the sandbox.
	if err := m2.Release("sb-tpl-a", true); err != nil {
		t.Fatalf("release after restart: %v", err)
	}
	if _, _, total = m2.Stats(); total != 2 {
		t.Fatalf("recycle keeps total, got %d", total)
	}
}
