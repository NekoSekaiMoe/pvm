package approval

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	return NewManager(nil)
}

func TestPersistenceRoundTripAndConsume(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "approvals.json")

	m1 := newTestManager(t)
	if err := m1.EnablePersistence(store); err != nil {
		t.Fatal(err)
	}
	id, err := m1.Create(Ticket{TaskID: "t-1", Tool: "deploy", Params: map[string]interface{}{"env": "prod"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m1.Decide(id, true, "op"); err != nil {
		t.Fatal(err)
	}

	// New manager loading the same store must see the approved ticket.
	m2 := newTestManager(t)
	if err := m2.EnablePersistence(store); err != nil {
		t.Fatal(err)
	}
	got, err := m2.Get(id)
	if err != nil || got.State != StateApproved {
		t.Fatalf("approved ticket must survive restart: %+v %v", got, err)
	}
	tid, ok := m2.ApprovedFor("t-1", "deploy", map[string]interface{}{"env": "prod"})
	if !ok || tid != id {
		t.Fatalf("ApprovedFor after restart: %q %v", tid, ok)
	}
	m2.MarkConsumed(id)
	if _, ok := m2.ApprovedFor("t-1", "deploy", map[string]interface{}{"env": "prod"}); ok {
		t.Fatal("consumed ticket must not unlock again")
	}
}

func TestEditOnlyPending(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.Create(Ticket{TaskID: "t-2", Tool: "pay", Params: map[string]interface{}{"amount": 10}})
	edited, err := m.Edit(id, map[string]interface{}{"amount": 5}, "lower the amount", "op")
	if err != nil {
		t.Fatalf("edit pending ticket: %v", err)
	}
	v, _ := edited.Params["amount"].(int)
	if v != 5 {
		t.Fatalf("params must be amended, got %+v", edited.Params)
	}
	if err := m.Decide(id, true, "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Edit(id, map[string]interface{}{"amount": 1}, "", "op"); err != ErrAlreadyDecided {
		t.Fatalf("decided ticket must be immutable, got %v", err)
	}
}

func TestApprovedForRequiresExactParams(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.Create(Ticket{TaskID: "t-3", Tool: "rm", Params: map[string]interface{}{"path": "/a"}})
	_ = m.Decide(id, true, "op")
	if _, ok := m.ApprovedFor("t-3", "rm", map[string]interface{}{"path": "/b"}); ok {
		t.Fatal("different params must not unlock")
	}
	if _, ok := m.ApprovedFor("t-3", "rm", map[string]interface{}{"path": "/a"}); !ok {
		t.Fatal("exact params must unlock")
	}
}

func TestExpirePending(t *testing.T) {
	m := newTestManager(t)
	m.now = func() time.Time { return time.Now().Add(-10 * time.Minute) }
	id, err := m.Create(Ticket{TaskID: "t-4", Tool: "x"})
	if err != nil {
		t.Fatal(err)
	}
	m.now = time.Now
	if n := m.ExpirePending(); n != 1 {
		t.Fatalf("expected 1 expiry, got %d", n)
	}
	tk, _ := m.Get(id)
	if tk.State != StateExpired {
		t.Fatalf("ticket must be expired, got %s", tk.State)
	}
}
