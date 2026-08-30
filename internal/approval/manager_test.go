package approval

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uml-container/internal/audit"
)

func tmpLedger(t *testing.T) *audit.Ledger {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("approval-test")
	return l
}

func TestCreateApprove_Flow(t *testing.T) {
	m := NewManager(tmpLedger(t))
	id, err := m.Create(Ticket{
		TaskID: "t1",
		Tool:   "send_email",
		Target: "prod-mailer",
		Params: map[string]interface{}{"to": "user@example.com", "subject": "hi"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if m.IsApproved("t1", "send_email", map[string]interface{}{"to": "user@example.com", "subject": "hi"}) {
		t.Error("should NOT be auto-approved before decision")
	}
	if err := m.Decide(id, true, "alice"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !m.IsApproved("t1", "send_email", map[string]interface{}{"to": "user@example.com", "subject": "hi"}) {
		t.Error("should be approved after decision")
	}
	// different params must NOT be covered by the same approval
	if m.IsApproved("t1", "send_email", map[string]interface{}{"to": "attacker@example.com", "subject": "hi"}) {
		t.Error("approval bled into different params (param binding broken)")
	}
}

func TestCreate_Dedup(t *testing.T) {
	m := NewManager(tmpLedger(t))
	_, err := m.Create(Ticket{TaskID: "t", Tool: "x", Params: map[string]interface{}{"a": 1}})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err = m.Create(Ticket{TaskID: "t", Tool: "x", Params: map[string]interface{}{"a": 1}})
	if err != ErrAlreadyPending {
		t.Errorf("expected ErrAlreadyPending, got %v", err)
	}
}

func TestDecide_Reject(t *testing.T) {
	m := NewManager(tmpLedger(t))
	id, _ := m.Create(Ticket{TaskID: "t", Tool: "x"})
	if err := m.Decide(id, false, "bob"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if m.IsApproved("t", "x", nil) {
		t.Error("rejected ticket should not count as approved")
	}
}

// TestCreate_DefaultDeadlineIsServerNowPlus5m pins the default-deadline
// semantics: the approval window is 5 minutes from the MANAGER's clock, and
// a caller-supplied CreatedAt must NOT be used as the basis (a forged
// future CreatedAt used to extend the ticket's life beyond now+5m).
func TestCreate_DefaultDeadlineIsServerNowPlus5m(t *testing.T) {
	m := NewManager(nil)
	m.now = func() time.Time { return baseTime }

	id, err := m.Create(Ticket{TaskID: "t", Tool: "x"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tk, err := m.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !tk.Deadline.Equal(baseTime.Add(5 * time.Minute)) {
		t.Errorf("default deadline = %s, want %s (now+5m)", tk.Deadline, baseTime.Add(5*time.Minute))
	}
}

// TestCreate_ForgedCreatedAtCannotExtendDefaultDeadline: a backdated or
// future-forged CreatedAt must not lengthen the default approval window —
// the deadline stays anchored to server-side now.
func TestCreate_ForgedCreatedAtCannotExtendDefaultDeadline(t *testing.T) {
	m := NewManager(nil)
	m.now = func() time.Time { return baseTime }

	// CreatedAt forged 1h in the past: old code would set deadline at
	// CreatedAt+5m (already expired, ticket dead on arrival) — a denial, not
	// an extension; the meaningful attack is the future-forged case below.
	idPast, err := m.Create(Ticket{TaskID: "t-past", Tool: "x", CreatedAt: baseTime.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("create(past): %v", err)
	}
	tkPast, _ := m.Get(idPast)
	want := baseTime.Add(5 * time.Minute)
	if !tkPast.Deadline.Equal(want) {
		t.Errorf("backdated CreatedAt: deadline = %s, want %s (server now+5m)", tkPast.Deadline, want)
	}

	// CreatedAt forged 1h in the future: old code would set deadline at
	// CreatedAt+5m, extending the ticket's life by an hour. Must stay now+5m.
	idFuture, err := m.Create(Ticket{TaskID: "t-future", Tool: "x", CreatedAt: baseTime.Add(time.Hour)})
	if err != nil {
		t.Fatalf("create(future): %v", err)
	}
	tkFuture, _ := m.Get(idFuture)
	if !tkFuture.Deadline.Equal(want) {
		t.Errorf("forged future CreatedAt extended deadline: got %s, want %s", tkFuture.Deadline, want)
	}
}

// TestCreate_ExplicitDeadlineOutsideWindowRejected keeps the window
// semantics for explicit deadlines: they must lie in [now, now+1h] on the
// MANAGER's clock, regardless of the caller-supplied CreatedAt.
func TestCreate_ExplicitDeadlineOutsideWindowRejected(t *testing.T) {
	m := NewManager(nil)
	m.now = func() time.Time { return baseTime }

	cases := []struct {
		name    string
		ticket  Ticket
		wantErr error
	}{
		{
			// already expired relative to server now
			name:    "past deadline",
			ticket:  Ticket{TaskID: "t1", Tool: "x", Deadline: baseTime.Add(-time.Minute)},
			wantErr: ErrInvalidDeadline,
		},
		{
			// more than 1h out
			name:    "far-future deadline",
			ticket:  Ticket{TaskID: "t2", Tool: "x", Deadline: baseTime.Add(90 * time.Minute)},
			wantErr: ErrInvalidDeadline,
		},
		{
			// a forged future CreatedAt must not launder an out-of-window deadline
			name: "forged CreatedAt laundering deadline",
			ticket: Ticket{
				TaskID:    "t3",
				Tool:      "x",
				CreatedAt: baseTime.Add(2 * time.Hour),
				// > now+1h even though <= CreatedAt+1h
				Deadline: baseTime.Add(115 * time.Minute),
			},
			wantErr: ErrInvalidDeadline,
		},
		{
			// in-window explicit deadline still accepted
			name:    "valid explicit deadline accepted",
			ticket:  Ticket{TaskID: "t4", Tool: "x", Deadline: baseTime.Add(30 * time.Minute)},
			wantErr: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.Create(tc.ticket)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Errorf("valid explicit deadline rejected: %v", err)
			}
		})
	}
}

func TestDecide_AlreadyDecided(t *testing.T) {
	m := NewManager(tmpLedger(t))
	id, _ := m.Create(Ticket{TaskID: "t", Tool: "x"})
	_ = m.Decide(id, true, "alice")
	if err := m.Decide(id, false, "alice"); err != ErrAlreadyDecided {
		t.Errorf("expected ErrAlreadyDecided, got %v", err)
	}
}

func TestPending_ExpiryLazy(t *testing.T) {
	m := NewManager(tmpLedger(t))
	m.now = func() time.Time {
		// Create time: now
		return baseTime
	}
	// Create with deadline derived from CreatedAt+5m
	id, _ := m.Create(Ticket{TaskID: "t", Tool: "x"})
	_ = id

	// advance clock past deadline
	m.now = func() time.Time { return baseTime.Add(10 * time.Minute) }
	pending := m.Pending("")
	if len(pending) != 0 {
		t.Errorf("expected no pending after expiry, got %d", len(pending))
	}
}

var baseTime = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

// TestSameParams_NestedMapDoesNotPanic is the regression test for the
// comparing-uncomparable panic: Params comes from JSON decoding and routinely
// contains nested maps/slices. The old ==-based comparison panicked at
// runtime on such inputs; the JSON-based one must not.
func TestSameParams_NestedMapDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("sameParams panicked on nested map: %v", r)
		}
	}()
	a := map[string]interface{}{
		"to":   "x@y.com",
		"opts": map[string]interface{}{"cc": []interface{}{"a@b.com"}},
		"tags": []interface{}{1, 2, 3},
	}
	b := map[string]interface{}{
		"to":   "x@y.com",
		"opts": map[string]interface{}{"cc": []interface{}{"a@b.com"}},
		"tags": []interface{}{1, 2, 3},
	}
	if !sameParams(a, b) {
		t.Error("expected nested maps to compare equal")
	}
	// A different nested value must compare unequal, not panic.
	c := map[string]interface{}{"opts": map[string]interface{}{"cc": []interface{}{"other"}}}
	if sameParams(a, c) {
		t.Error("expected nested-differing params to compare unequal")
	}
}

// TestCreate_DedupNestedParams exercises the same path through Create: a
// duplicate ticket with nested params must be deduped (ErrAlreadyPending),
// not crash the manager.
func TestCreate_DedupNestedParams(t *testing.T) {
	m := NewManager(nil)
	params := map[string]interface{}{
		"target": "prod",
		"env":    map[string]interface{}{"region": "us-east-1"},
	}
	if _, err := m.Create(Ticket{TaskID: "t", Tool: "deploy", Params: params}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := m.Create(Ticket{TaskID: "t", Tool: "deploy", Params: params}); err != ErrAlreadyPending {
		t.Errorf("expected ErrAlreadyPending, got %v", err)
	}
}

// TestClaimFor_ConcurrentClaimsConsumeOnce is the PR #22 review regression:
// find+consume+persist must be atomic so concurrent gateway executions can
// never both unlock on the same approved ticket.
func TestClaimFor_ConcurrentClaimsConsumeOnce(t *testing.T) {
	m := NewManager(tmpLedger(t))
	id, err := m.Create(Ticket{
		TaskID:   "t-race",
		Tool:     "push",
		Params:   map[string]interface{}{"ref": "main"},
		Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := m.Decide(id, true, "operator"); err != nil {
		t.Fatalf("decide: %v", err)
	}

	var (
		wg      sync.WaitGroup
		winners int64
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := m.ClaimFor("t-race", "push", map[string]interface{}{"ref": "main"}); ok {
				atomic.AddInt64(&winners, 1)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("exactly one concurrent claim must win, got %d", winners)
	}
	if _, ok := m.ApprovedFor("t-race", "push", map[string]interface{}{"ref": "main"}); ok {
		t.Fatal("claimed ticket must not remain claimable")
	}
}

// TestMarkConsumedRollsBackWhenPersistFails: a consume that cannot be
// persisted must not stick in memory either — the store file is what a
// restart replays, so a memory-only burn would make the ticket look spent
// in-process while still consumable after a restart (the replay hazard
// ClaimFor refuses). The store is broken by replacing the file with a
// directory: fsjson's atomic rename onto a directory fails (EISDIR).
func TestMarkConsumedRollsBackWhenPersistFails(t *testing.T) {
	m := NewManager(nil)
	path := filepath.Join(t.TempDir(), "approvals.json")
	if err := m.EnablePersistence(path); err != nil {
		t.Fatalf("enable persistence: %v", err)
	}
	id, err := m.Create(Ticket{
		TaskID:   "t1",
		Tool:     "deploy",
		Target:   "prod",
		Params:   map[string]interface{}{"ref": "v1"},
		Why:      "ship the fix",
		Rollback: "kubectl rollout undo",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := m.Decide(id, true, "alice"); err != nil {
		t.Fatalf("decide: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove store: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("plant broken store: %v", err)
	}

	m.MarkConsumed(id)
	got, err := m.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Consumed {
		t.Fatal("MarkConsumed left Consumed=true in memory after a failed persist (rollback missing)")
	}
	if !m.IsApproved("t1", "deploy", map[string]interface{}{"ref": "v1"}) {
		t.Fatal("ticket must remain approved-unconsumed after the rolled-back burn")
	}
}

// TestEnablePersistenceReadErrorDoesNotClobber: when the store path exists
// but cannot be READ (EISDIR here; EACCES in production), EnablePersistence
// must fail instead of "recovering" into an empty store — the persist that
// follows would atomically replace the unreadable file and permanently
// delete every pending/approved ticket (same policy as identity/persist.go).
func TestEnablePersistenceReadErrorDoesNotClobber(t *testing.T) {
	m := NewManager(nil)
	if err := m.EnablePersistence(t.TempDir()); err == nil {
		t.Fatal("EnablePersistence must fail when the store cannot be read")
	}
	// Retry on a good path still works and really writes.
	good := filepath.Join(t.TempDir(), "approvals.json")
	if err := m.EnablePersistence(good); err != nil {
		t.Fatalf("re-enable on a good path: %v", err)
	}
	if _, err := os.Stat(good); err != nil {
		t.Fatalf("good store not written: %v", err)
	}
}
