package pool

import (
	"errors"
	"strings"
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

// TestClaim_QuotaHourlyRecheckAfterFactory is the regression test for the
// phase-3 race: the post-Factory recheck used to verify concurrency/cpu/mem
// but NOT the hourly rate, so MaxConcurrent concurrent claims could together
// exceed MaxTasksPerHour. Here MaxTasksPerHour=1 and the factory blocks until
// a second claim sneaks in; the first claim must be rejected after the factory
// returns instead of committing.
func TestClaim_QuotaHourlyRecheckAfterFactory(t *testing.T) {
	m := NewManager(10, nil)
	m.SetQuota("t", Quota{MaxConcurrent: 10, MaxCPU: 99, MaxMemoryMB: 99999, MaxTasksPerHour: 1})
	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}

	factoryEntered := make(chan struct{})
	releaseFactory := make(chan struct{})
	// Warm with a Factory that returns immediately: the placeholder path
	// (nil Factory) would leave a READY sandbox that the FIRST claim below
	// would claim instead of entering the blocking factory.
	m.Factory = func(Template) (string, error) { return "warm-1", nil }
	m.Warm(tmpl, 1) // warm first: Warm also invokes Factory
	m.Factory = func(Template) (string, error) {
		close(factoryEntered)
		<-releaseFactory
		return "ondemand-raced", nil
	}
	// tmpl2 deliberately uses a DIFFERENT template name: a claim for "x"
	// would take the warm sandbox above and never enter the blocking factory.
	tmpl2 := Template{Name: "y", Memory: "128M", CPU: 1}

	// First claim passes phase 1 (hourly: 0/1) and enters the factory.
	type claimResult struct {
		id  string
		err error
	}
	res := make(chan claimResult, 1)
	go func() {
		id, err := m.Claim("t", tmpl2, "task-2")
		res <- claimResult{id, err}
	}()
	<-factoryEntered

	// While the factory is stuck, a second claim consumes the hourly budget
	// via the pre-warmed sandbox.
	if _, err := m.Claim("t", tmpl, "task-1"); err != nil {
		t.Fatalf("second claim should succeed within the hourly quota: %v", err)
	}

	// Release the factory: the first claim's phase-3 recheck must now see the
	// exhausted hourly rate and reject.
	close(releaseFactory)
	r := <-res
	if !errors.Is(r.err, ErrQuotaExceeded) {
		t.Fatalf("first claim must be denied after hourly recheck, got id=%q err=%v", r.id, r.err)
	}
	if _, _, total := m.Stats(); total != 1 {
		t.Errorf("raced on-demand sandbox leaked into the pool: total=%d", total)
	}
}

// TestClaim_BadTemplateMemoryRejected pins strict memory parsing at the claim
// boundary: an unparseable template memory must be a hard error, never a
// silent 0/1MB accounting.
func TestClaim_BadTemplateMemoryRejected(t *testing.T) {
	m := NewManager(10, nil)
	tmpl := Template{Name: "x", Memory: "1.5G", CPU: 1}
	if _, err := m.Claim("t", tmpl, "task"); err == nil {
		t.Fatal("claim with unparseable template memory must fail")
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
	// KB values round UP to whole MB (a value below 1024 KB still costs at
	// least 1 MB of quota); exact multiples are unchanged.
	valid := map[string]int{"512M": 512, "2G": 2048, "1024K": 1, "1K": 1, "1023K": 1, "1GB": 1024, "0M": 0, "0K": 0}
	for in, want := range valid {
		t.Run(in, func(t *testing.T) {
			got, err := parseMemMB(in)
			if err != nil {
				t.Fatalf("parseMemMB(%q) unexpected error: %v", in, err)
			}
			if got != want {
				t.Errorf("parseMemMB(%q) = %d, want %d", in, got, want)
			}
		})
	}
	// Strict parsing: malformed values and unknown/missing units are errors,
	// never silent fallbacks ("1.5G" used to parse as 1 MB).
	invalid := []string{"", "1.5G", "512", "512X", "M", "abc", "-512M", "1 Ti"}
	for _, in := range invalid {
		t.Run(in, func(t *testing.T) {
			if got, err := parseMemMB(in); err == nil {
				t.Errorf("parseMemMB(%q) = %d, want error", in, got)
			}
		})
	}
}

// TestRelease_RecyclesQuota is the regression test for the quota-leak bug:
// before the fix, Release decremented m.running[taskID] (not the real tenant)
// and never decremented cpu/memMB at all, so a tenant that claimed+released
// repeatedly hit ErrQuotaExceeded forever. We claim to the MaxConcurrent cap,
// release, and confirm a subsequent claim on the same quota succeeds.
func TestRelease_RecyclesQuota(t *testing.T) {
	m := NewManager(10, tmpLedger(t))
	m.SetQuota("tenant", Quota{MaxConcurrent: 1, MaxCPU: 4, MaxMemoryMB: 512, MaxTasksPerHour: 100})
	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	// Pre-warm one sandbox so Claim has something to hand out.
	m.Warm(tmpl, 1)

	// First claim fills the MaxConcurrent: 1 quota.
	id1, err := m.Claim("tenant", tmpl, "task-1")
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// A second concurrent claim for the same tenant must be denied.
	if _, err := m.Claim("tenant", tmpl, "task-1b"); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected quota denial on second claim, got %v", err)
	}
	// Recycle the first sandbox: this MUST release the quota counters.
	if err := m.Release(id1, true); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Now the same tenant must be able to claim again. Pre-fix this failed
	// permanently because running/cpu/memMB never got decremented.
	if _, err := m.Claim("tenant", tmpl, "task-2"); err != nil {
		t.Fatalf("claim after release failed (quota leaked): %v", err)
	}
}

// TestRelease_DestroyRecyclesQuota is the destroy-path sibling of the above.
func TestRelease_DestroyRecyclesQuota(t *testing.T) {
	m := NewManager(10, tmpLedger(t))
	m.SetQuota("tenant", Quota{MaxConcurrent: 1, MaxCPU: 4, MaxMemoryMB: 512, MaxTasksPerHour: 100})
	m.Destroyer = func(string) error { return nil }
	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	m.Warm(tmpl, 1)

	id1, err := m.Claim("tenant", tmpl, "task-1")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := m.Release(id1, false); err != nil {
		t.Fatalf("release destroy: %v", err)
	}
	// Need a fresh warm sandbox to claim against (the previous one was destroyed).
	m.Warm(tmpl, 1)
	if _, err := m.Claim("tenant", tmpl, "task-2"); err != nil {
		t.Fatalf("claim after destroy failed (quota leaked): %v", err)
	}
}

// TestRelease_DestroyErrorPropagates ensures a failing Destroyer is surfaced
// to the caller (previously its error was silently dropped), AND that the
// quota is still released even when Destroy fails — otherwise a tenant whose
// destroyer is flaky would permanently leak quota and be unable to claim again.
func TestRelease_DestroyErrorPropagates(t *testing.T) {
	m := NewManager(10, tmpLedger(t))
	m.Destroyer = func(string) error { return errors.New("boom") }
	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	// Cap concurrency at 1 so the post-destroy re-claim is the real test of
	// whether quota was released.
	m.SetQuota("tenant", Quota{MaxConcurrent: 1, MaxCPU: 4, MaxMemoryMB: 512, MaxTasksPerHour: 100})
	m.Warm(tmpl, 1)
	id, _ := m.Claim("tenant", tmpl, "task")
	err := m.Release(id, false)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected destroyer error to propagate, got %v", err)
	}
	// Quota MUST have been released despite the destroy error, so the same
	// tenant can claim again once a fresh warm sandbox is available.
	m.Warm(tmpl, 1)
	if _, err := m.Claim("tenant", tmpl, "task-2"); err != nil {
		t.Errorf("claim after destroy failure was denied (quota leaked despite error propagation): %v", err)
	}
}
