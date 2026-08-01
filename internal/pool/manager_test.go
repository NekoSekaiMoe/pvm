package pool

import (
	"errors"
	"testing"

	"uml-container/internal/audit"
)

func tmpLedger(t *testing.T) *audit.Ledger {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("pool-test")
	return l
}

func TestWarm_AndClaim(t *testing.T) {
	m := NewManager(10, tmpLedger(t))
	tmpl := Template{Name: "alpine", BaseImage: "alpine.img", Kernel: "linux", Memory: "512M", CPU: 1}
	if n := m.Warm(tmpl, 3); n != 3 {
		t.Fatalf("warmed %d, want 3", n)
	}
	ready, claimed, total := m.Stats()
	if ready != 3 || claimed != 0 || total != 3 {
		t.Errorf("stats: ready=%d claimed=%d total=%d", ready, claimed, total)
	}
	id, err := m.Claim("tenant-a", tmpl, "task-1")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if id == "" {
		t.Fatal("empty id")
	}
	ready, claimed, _ = m.Stats()
	if ready != 2 || claimed != 1 {
		t.Errorf("after claim: ready=%d claimed=%d", ready, claimed)
	}
}

func TestClaim_QuotaConcurrency(t *testing.T) {
	m := NewManager(10, tmpLedger(t))
	m.SetQuota("t", Quota{MaxConcurrent: 1, MaxCPU: 10, MaxMemoryMB: 99999, MaxTasksPerHour: 99})
	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	m.Warm(tmpl, 3)

	if _, err := m.Claim("t", tmpl, "a"); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	_, err := m.Claim("t", tmpl, "b")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected quota error, got %v", err)
	}
}

func TestClaim_QuotaHourly(t *testing.T) {
	m := NewManager(10, tmpLedger(t))
	m.SetQuota("t", Quota{MaxConcurrent: 99, MaxCPU: 99, MaxMemoryMB: 99999, MaxTasksPerHour: 2})
	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	m.Warm(tmpl, 5)

	for i := 0; i < 2; i++ {
		if _, err := m.Claim("t", tmpl, "x"); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
	}
	_, err := m.Claim("t", tmpl, "x")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected hourly quota error, got %v", err)
	}
}

func TestRelease_Recycle(t *testing.T) {
	m := NewManager(10, tmpLedger(t))
	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	m.Warm(tmpl, 1)
	id, _ := m.Claim("tenant-x", tmpl, "task")
	if err := m.Release(id, true); err != nil {
		t.Fatalf("release: %v", err)
	}
	ready, _, _ := m.Stats()
	if ready != 1 {
		t.Errorf("after recycle, ready should be 1, got %d", ready)
	}
}

func TestRelease_Destroy(t *testing.T) {
	destroyed := false
	m := NewManager(10, tmpLedger(t))
	m.Destroyer = func(string) error { destroyed = true; return nil }
	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	m.Warm(tmpl, 1)
	id, _ := m.Claim("tenant-x", tmpl, "task")
	if err := m.Release(id, false); err != nil {
		t.Fatalf("release: %v", err)
	}
	if !destroyed {
		t.Error("destroyer not called on non-recycle release")
	}
	_, _, total := m.Stats()
	if total != 0 {
		t.Errorf("after destroy, total should be 0, got %d", total)
	}
}

func TestClaim_OnDemandCreation(t *testing.T) {
	m := NewManager(5, tmpLedger(t))
	m.Factory = func(t Template) (string, error) { return "ondemand-1", nil }
	tmpl := Template{Name: "fresh", Memory: "256M", CPU: 1}
	id, err := m.Claim("tenant", tmpl, "task")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if id != "ondemand-1" {
		t.Errorf("expected on-demand id, got %s", id)
	}
}

func TestParseMemMB(t *testing.T) {
	cases := map[string]int{"512M": 512, "2G": 2048, "1024K": 1, "1024": 1024}
	for in, want := range cases {
		if got := parseMemMB(in); got != want {
			t.Errorf("parseMemMB(%q) = %d, want %d", in, got, want)
		}
	}
}
