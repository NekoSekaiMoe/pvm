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

func TestLedger_HeadAtomicWrite(t *testing.T) {
	tmp := t.TempDir()
	LedgerRoot = tmp

	l, err := Open("head-atomic")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := l.Append(Record{Phase: PhaseExec, Subject: "agent", Action: "read", Decision: DecisionAllow}); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	oldSeq, oldHash, ok := l.readHead()
	if !ok || oldSeq != 1 {
		t.Fatalf("after first append: readHead ok=%v seq=%d want seq=1", ok, oldSeq)
	}

	// Simulate a crash between temp-file creation and rename: a stale temp
	// with partial content must never become visible via readHead — the old
	// watermark stays intact until the atomic rename lands the new one.
	taskDir := filepath.Join(tmp, "head-atomic")
	stale := filepath.Join(taskDir, ".head.tmp-crashed1234")
	if err := os.WriteFile(stale, []byte("7 half"), 0600); err != nil {
		t.Fatalf("seed stale temp: %v", err)
	}
	if seq, _, ok := l.readHead(); !ok || seq != oldSeq {
		t.Fatalf("stale temp leaked into readHead: ok=%v seq=%d want %d", ok, seq, oldSeq)
	}

	// A later Append replaces the watermark atomically: readHead sees the
	// complete new value (never the stale temp or a torn blend of both).
	if err := l.Append(Record{Phase: PhaseExec, Subject: "agent", Action: "write", Decision: DecisionDeny}); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	recs, err := l.ReadAll()
	if err != nil || len(recs) != 2 {
		t.Fatalf("readall: %v len=%d", err, len(recs))
	}
	seq, hash, ok := l.readHead()
	if !ok || seq != 2 || hash != recs[1].ThisHash || hash == oldHash {
		t.Fatalf("readHead after atomic replace: ok=%v seq=%d hash mismatch", ok, seq)
	}

	// The replacement landed at the target path with 0600, and the success
	// path left no fresh temp debris of its own (the simulated crash artifact
	// is pre-existing and not this Append's responsibility).
	fi, err := os.Stat(filepath.Join(taskDir, "head"))
	if err != nil {
		t.Fatalf("stat head: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("head mode = %o, want 0600", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	tmps := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".head.tmp-") {
			tmps++
		}
	}
	if tmps != 1 { // only the simulated crash artifact remains
		t.Errorf("expected exactly the stale temp to remain, found %d temp files", tmps)
	}

	// The whole ledger still verifies end-to-end against the new watermark.
	l2, _ := Open("head-atomic")
	if n, err := l2.Verify(); err != nil || n != 2 {
		t.Fatalf("verify after atomic writes: n=%d err=%v", n, err)
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
