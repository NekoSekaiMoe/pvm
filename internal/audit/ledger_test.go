package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLedger_ChainAndVerify(t *testing.T) {
	tmp := t.TempDir()
	LedgerRoot = tmp

	l, err := Open("task-1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Append(Record{
			Phase:    PhaseExec,
			Subject:  "agent",
			Action:   "read",
			Params:   map[string]interface{}{"path": "/etc/hosts", "i": i},
			Decision: DecisionAllow,
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// verify a freshly opened ledger (re-reads tail from disk)
	l2, err := Open("task-1")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	n, err := l2.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 5 {
		t.Errorf("verified count = %d, want 5", n)
	}
}

func TestLedger_TamperDetected(t *testing.T) {
	tmp := t.TempDir()
	LedgerRoot = tmp

	l, _ := Open("task-2")
	l.Append(Record{Phase: PhaseExec, Subject: "agent", Action: "read", Decision: DecisionAllow})
	l.Append(Record{Phase: PhaseExec, Subject: "agent", Action: "write", Decision: DecisionDeny, Reason: "outside branch"})

	// tamper: rewrite the file with a modified reason on row 2
	path := filepath.Join(tmp, "task-2", "ledger.jsonl")
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), "outside branch", "approved", 1)
	os.WriteFile(path, []byte(tampered), 0644)

	l2, _ := Open("task-2")
	_, err := l2.Verify()
	if err == nil {
		t.Fatal("expected tamper detection error, got nil")
	}
	if !strings.Contains(err.Error(), "broken chain") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLedger_CrossTaskIsolation(t *testing.T) {
	tmp := t.TempDir()
	LedgerRoot = tmp

	a, _ := Open("a")
	b, _ := Open("b")
	a.Append(Record{Phase: PhaseGoalAuth, Subject: "alice", Action: "auth", Decision: DecisionAllow})
	b.Append(Record{Phase: PhaseGoalAuth, Subject: "bob", Action: "auth", Decision: DecisionAllow})

	la, _ := a.ReadAll()
	lb, _ := b.ReadAll()
	if len(la) != 1 || len(lb) != 1 {
		t.Fatalf("isolation broken: la=%d lb=%d", len(la), len(lb))
	}
	if la[0].Task != "a" || lb[0].Task != "b" {
		t.Errorf("task scoping wrong")
	}
}
