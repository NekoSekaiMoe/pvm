package approval

import (
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
