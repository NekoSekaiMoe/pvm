package pool

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestParseMemMB_KBMaxNoOverflow pins the overflow fix in the K→MB path:
// the legacy (v+1023)/1024 formula wrapped negative on the largest int64 KB
// value; the quotient+remainder form must yield the exact rounded-up MB
// count (or a clean rejection where int is 32-bit).
func TestParseMemMB_KBMaxNoOverflow(t *testing.T) {
	var maxK int64 = math.MaxInt64
	// Legacy-behavior contrast: the pre-add wraps here (var, not const, so
	// the deliberate overflow compiles). This documents the old bug.
	legacy := (maxK + 1023) / 1024
	if legacy > 0 {
		t.Fatalf("precondition: legacy (v+1023)/1024 should wrap negative on MaxInt64 K, got %d", legacy)
	}
	in := fmt.Sprintf("%dK", maxK)
	want := maxK/1024 + 1 // MaxInt64 K = 1024*(2^53-1)+1023 K → 2^53 MB
	got, err := parseMemMB(in)
	if strconv.IntSize == 64 {
		if err != nil {
			t.Fatalf("parseMemMB(%q) unexpected error: %v", in, err)
		}
		if int64(got) != want {
			t.Errorf("parseMemMB(%q) = %d, want %d (no wrap, no truncation)", in, got, want)
		}
	} else {
		// On 32-bit int the MB count exceeds math.MaxInt32 and must be
		// rejected by the pre-conversion bound check, not truncated.
		if err == nil {
			t.Fatalf("parseMemMB(%q) = %d, want rejection (exceeds platform int max)", in, got)
		}
	}
}

// TestParseMemMB_IntBoundary checks the int-conversion bound: an MB count
// exactly at the platform int maximum is accepted; anything above it must be
// rejected with a clear error rather than silently wrapping in int(mb).
func TestParseMemMB_IntBoundary(t *testing.T) {
	maxInt := int64(math.MaxInt)
	atLimit := strconv.FormatInt(maxInt, 10) + "M"
	got, err := parseMemMB(atLimit)
	if err != nil {
		t.Fatalf("parseMemMB(%q) unexpected error: %v", atLimit, err)
	}
	if int64(got) != maxInt {
		t.Errorf("parseMemMB(%q) = %d, want %d", atLimit, got, maxInt)
	}
	// One MB beyond the platform int max must be rejected. This is only
	// expressible on 32-bit platforms: on 64-bit no M/K value can exceed
	// math.MaxInt (the G path already guards its own overflow upstream).
	if maxInt < math.MaxInt64 {
		over := strconv.FormatInt(maxInt+1, 10) + "M"
		if got, err := parseMemMB(over); err == nil {
			t.Errorf("parseMemMB(%q) = %d, want error (exceeds platform int max)", over, got)
		}
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

// TestClaim_MemoryQuotaOverflowSafe is the regression test for the int
// overflow in the stage-1 memory quota check: the legacy
// m.memMB[tenant]+wantMB > limit addition wraps when usage sits near
// math.MaxInt (a legal value per parseMemMB), turning an over-quota claim
// into a false ALLOW. The subtraction boundary check must reject it, and a
// rejection must NOT update the tenant's recorded memory usage.
func TestClaim_MemoryQuotaOverflowSafe(t *testing.T) {
	m := NewManager(10, nil)
	// Huge-but-valid limit: MaxMemoryMB at the platform int maximum.
	m.SetQuota("t", Quota{MaxConcurrent: 10, MaxCPU: 99, MaxMemoryMB: math.MaxInt, MaxTasksPerHour: 99})

	// First claim: usage 0 + (MaxInt-1024) <= MaxInt → allowed.
	big := strconv.FormatInt(int64(math.MaxInt)-1024, 10) + "M"
	tmplBig := Template{Name: "x", Memory: big, CPU: 1}
	m.Warm(tmplBig, 1)
	if _, err := m.Claim("t", tmplBig, "task-1"); err != nil {
		t.Fatalf("huge-but-valid claim: %v", err)
	}
	if got := m.memMB["t"]; got != math.MaxInt-1024 {
		t.Fatalf("recorded usage = %d, want %d", got, math.MaxInt-1024)
	}

	// Second claim: (MaxInt-1024)+2048 wraps int in the addition form — the
	// exact false-allow the subtraction check must close. Only 1024 MB of
	// headroom remain, so a 2G claim must be rejected.
	tmpl2G := Template{Name: "y", Memory: "2G", CPU: 1}
	m.Warm(tmpl2G, 1)
	if _, err := m.Claim("t", tmpl2G, "task-2"); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("overflowing claim must be rejected, got err=%v", err)
	}
	// The rejection must NOT have updated the recorded usage.
	if got := m.memMB["t"]; got != math.MaxInt-1024 {
		t.Fatalf("rejected claim updated recorded usage: %d, want %d", got, math.MaxInt-1024)
	}
	// A claim that FITS the remaining headroom (exactly 1024 MB) still
	// succeeds — the check is a boundary, not a blanket denial — and lands
	// usage exactly on the limit without wrapping.
	tmplFits := Template{Name: "z", Memory: "1024M", CPU: 1}
	m.Warm(tmplFits, 1)
	if _, err := m.Claim("t", tmplFits, "task-3"); err != nil {
		t.Fatalf("claim within remaining headroom: %v", err)
	}
	if got := m.memMB["t"]; got != math.MaxInt {
		t.Fatalf("recorded usage = %d, want exactly %d", got, math.MaxInt)
	}
}

// TestClaim_MemoryQuotaOverflowSafeAfterFactory is the stage-3 sibling of
// TestClaim_MemoryQuotaOverflowSafe: the post-Factory quota recheck had the
// same wrapping addition, so a claim that passed stage 1 could commit an
// over-limit sandbox after a concurrent claim filled the headroom near
// math.MaxInt.
func TestClaim_MemoryQuotaOverflowSafeAfterFactory(t *testing.T) {
	m := NewManager(10, nil)
	m.SetQuota("t", Quota{MaxConcurrent: 10, MaxCPU: 99, MaxMemoryMB: math.MaxInt, MaxTasksPerHour: 99})

	// tmpl2G has no warm sandbox; its claim goes through the Factory.
	tmpl2G := Template{Name: "ondemand", Memory: "2G", CPU: 1}
	factoryEntered := make(chan struct{})
	releaseFactory := make(chan struct{})
	m.Factory = func(Template) (string, error) {
		close(factoryEntered)
		<-releaseFactory
		return "ondemand-raced", nil
	}
	res := make(chan error, 1)
	go func() {
		_, err := m.Claim("t", tmpl2G, "task-2g")
		res <- err
	}()
	<-factoryEntered

	// While the factory is blocked, a warm claim pushes usage to
	// MaxInt-1024 — allowed at stage 1 (0 + MaxInt-1024 <= MaxInt).
	big := strconv.FormatInt(int64(math.MaxInt)-1024, 10) + "M"
	tmplBig := Template{Name: "x", Memory: big, CPU: 1}
	m.Factory = func(Template) (string, error) { return "warm-x", nil }
	m.Warm(tmplBig, 1)
	if _, err := m.Claim("t", tmplBig, "task-big"); err != nil {
		t.Fatalf("warm claim near MaxInt: %v", err)
	}

	// Release the factory: the stage-3 recheck must see only 1024 MB of
	// headroom and reject the 2G claim. The legacy addition wrapped
	// (MaxInt-1024)+2048 negative and ALLOWED it.
	close(releaseFactory)
	if err := <-res; !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("stage-3 recheck must reject the wrapping claim, got err=%v", err)
	}
	// The rejected claim must not have updated the recorded usage, and the
	// on-demand sandbox must not have leaked into the pool.
	if got := m.memMB["t"]; got != math.MaxInt-1024 {
		t.Fatalf("rejected claim updated recorded usage: %d, want %d", got, math.MaxInt-1024)
	}
	if _, _, total := m.Stats(); total != 1 {
		t.Errorf("raced on-demand sandbox leaked into the pool: total=%d", total)
	}
}

// TestClaim_HourlyQuotaPrunesExpiredAfterFactory is the regression test for
// the missing phase-3 prune: the post-Factory hourly recheck used to count
// entries older than an hour (phase 1 prunes them; phase 3 didn't), so a
// claim whose Factory crossed an hourly boundary was incorrectly rejected.
// The clock is pinned via the manager's now hook.
func TestClaim_HourlyQuotaPrunesExpiredAfterFactory(t *testing.T) {
	m := NewManager(10, nil)
	m.SetQuota("t", Quota{MaxConcurrent: 99, MaxCPU: 99, MaxMemoryMB: 99999, MaxTasksPerHour: 1})

	cur := time.Now()
	m.now = func() time.Time { return cur }

	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	// Pre-warm with an instant factory, then install the blocking one (the
	// warm claim below must not enter it).
	m.Factory = func(Template) (string, error) { return "warm-1", nil }
	m.Warm(tmpl, 1)
	tmpl2 := Template{Name: "y", Memory: "128M", CPU: 1}
	factoryEntered := make(chan struct{})
	releaseFactory := make(chan struct{})
	m.Factory = func(Template) (string, error) {
		close(factoryEntered)
		<-releaseFactory
		// The provision took over an hour: phase 3 runs with the clock past
		// the hourly boundary of the entry added meanwhile.
		cur = cur.Add(time.Hour + time.Minute)
		return "ondemand-crossed", nil
	}

	type claimResult struct {
		id  string
		err error
	}
	res := make(chan claimResult, 1)
	go func() {
		id, err := m.Claim("t", tmpl2, "task-cross")
		res <- claimResult{id, err}
	}()
	<-factoryEntered

	// While the factory is blocked, a second claim spends the hourly budget.
	if _, err := m.Claim("t", tmpl, "task-warm"); err != nil {
		t.Fatalf("warm claim within hourly quota: %v", err)
	}
	// hourly = [cur] with MaxTasksPerHour = 1.

	close(releaseFactory)
	r := <-res
	// The warm claim's timestamp is now over an hour old: phase 3 must
	// prune it before the recheck instead of rejecting the claim.
	if r.err != nil {
		t.Fatalf("claim crossing an hourly boundary must not be rejected: %v", r.err)
	}
	// The expired entry was removed; only the fresh claim remains.
	m.mu.Lock()
	window := m.hourly["t"]
	m.mu.Unlock()
	if len(window) != 1 || !window[0].Equal(cur) {
		t.Errorf("hourly window = %v, want exactly the fresh entry %v (expired entry pruned)", window, cur)
	}
}

// TestClaim_FailedCleanupQueuedAndRetried: when a post-Factory recheck
// rejects a claim, the freshly built sandbox must be torn down — and if that
// teardown FAILS, the id and reason must be recorded and retried instead of
// being silently discarded (the old `_ = m.Destroyer(id)` leak), while the
// caller still gets the original rejection.
func TestClaim_FailedCleanupQueuedAndRetried(t *testing.T) {
	m := NewManager(10, nil)
	m.SetQuota("t", Quota{MaxConcurrent: 10, MaxCPU: 99, MaxMemoryMB: 99999, MaxTasksPerHour: 1})

	tmpl := Template{Name: "x", Memory: "128M", CPU: 1}
	m.Factory = func(Template) (string, error) { return "warm-1", nil }
	m.Warm(tmpl, 1)
	tmpl2 := Template{Name: "y", Memory: "128M", CPU: 1}
	factoryEntered := make(chan struct{})
	releaseFactory := make(chan struct{})
	m.Factory = func(Template) (string, error) {
		close(factoryEntered)
		<-releaseFactory
		return "ondemand-raced", nil
	}
	// The destroyer fails on every attempt during the rejection path.
	m.Destroyer = func(string) error { return errors.New("destroy down") }

	res := make(chan error, 1)
	go func() {
		_, err := m.Claim("t", tmpl2, "task-raced")
		res <- err
	}()
	<-factoryEntered
	// Spend the hourly budget while the factory is blocked, so the blocked
	// claim is rejected by the phase-3 recheck after the factory returns.
	if _, err := m.Claim("t", tmpl, "task-warm"); err != nil {
		t.Fatalf("warm claim within hourly quota: %v", err)
	}
	close(releaseFactory)

	// The rejection is preserved for the caller.
	if err := <-res; !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("claim must still be rejected, got err=%v", err)
	}
	// The failed teardown was recorded (id + reason), not discarded.
	if got := m.PendingCleanups(); got != 1 {
		t.Fatalf("pending cleanups = %d, want 1", got)
	}
	m.mu.Lock()
	reason, queued := m.pendingCleanups["ondemand-raced"]
	m.mu.Unlock()
	if !queued {
		t.Fatal("failed teardown of the raced sandbox was not recorded")
	}
	if !strings.Contains(reason, "hourly") {
		t.Errorf("cleanup reason = %q, want it to mention the hourly recheck", reason)
	}

	// A failed retry keeps it queued for the next sweep...
	m.RetryCleanups()
	if got := m.PendingCleanups(); got != 1 {
		t.Fatalf("persistent failure must stay queued, got %d", got)
	}
	// ...a successful retry clears it.
	destroyed := make(chan string, 1)
	m.Destroyer = func(id string) error { destroyed <- id; return nil }
	m.RetryCleanups()
	if got := m.PendingCleanups(); got != 0 {
		t.Fatalf("successful retry must clear the queue, got %d", got)
	}
	select {
	case id := <-destroyed:
		if id != "ondemand-raced" {
			t.Errorf("retry destroyed %q, want ondemand-raced", id)
		}
	default:
		t.Error("retry sweep did not attempt destruction")
	}
}

// TestRetryCleanups_ConcurrentSweepsSerialized pins the cleanupSweeping
// contract: two concurrent RetryCleanups must not both run Destroyer over
// the same queue. The Destroyer blocks on a gate; with serialization the
// second sweep returns immediately while the first is still inside
// Destroyer, so every sandbox is destroyed exactly once. Without the flag
// both sweeps snapshot the queue and each destroys every id twice.
func TestRetryCleanups_ConcurrentSweepsSerialized(t *testing.T) {
	m := NewManager(2, tmpLedger(t))
	m.mu.Lock()
	m.pendingCleanups["a"] = "test"
	m.pendingCleanups["b"] = "test"
	m.mu.Unlock()

	gate := make(chan struct{})
	var mu sync.Mutex
	calls := make(map[string]int)
	m.Destroyer = func(id string) error {
		<-gate
		mu.Lock()
		calls[id]++
		mu.Unlock()
		return nil
	}

	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			m.RetryCleanups()
			done <- struct{}{}
		}()
	}
	// With serialization the second sweep returns while the first is still
	// blocked inside Destroyer; without it BOTH block and nobody returns
	// until the gate opens — open it after a grace period either way.
	got := 0
	select {
	case <-done:
		got = 1
	case <-time.After(500 * time.Millisecond):
	}
	close(gate)
	for got < 2 {
		select {
		case <-done:
			got++
		case <-time.After(2 * time.Second):
			t.Fatal("RetryCleanups did not return")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for id, n := range calls {
		if n != 1 {
			t.Fatalf("sandbox %q destroyed %d times, want exactly 1 (sweeps must serialize)", id, n)
		}
	}
	if got := m.PendingCleanups(); got != 0 {
		t.Fatalf("pending cleanups = %d, want 0 after successful sweep", got)
	}
}
