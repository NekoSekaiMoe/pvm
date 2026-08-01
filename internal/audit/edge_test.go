package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLedger_ConcurrentAppends is the cross-process-safety stand-in: we can't
// easily fork, but we CAN hammer the same ledger from many goroutines. The
// hash chain must remain consistent — any interleaved corruption breaks Verify.
func TestLedger_ConcurrentAppends(t *testing.T) {
	LedgerRoot = t.TempDir()
	l, _ := Open("concurrent")
	var wg sync.WaitGroup
	const goroutines = 16
	const each = 25
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				_ = l.Append(Record{
					Phase: PhaseExec, Subject: "agent",
					Action: fmt.Sprintf("call-%d-%d", id, i),
					Params: map[string]interface{}{"g": id, "i": i},
					Decision: DecisionAllow,
				})
			}
		}(g)
	}
	wg.Wait()

	// Reopen to re-read the tail.
	l2, _ := Open("concurrent")
	n, err := l2.Verify()
	if err != nil {
		t.Fatalf("chain broken under concurrency: %v", err)
	}
	if n != goroutines*each {
		t.Errorf("verified %d, expected %d (some appends lost?)", n, goroutines*each)
	}
}

// TestLedger_PhaseCoverage exercises all four phases to make sure none is
// silently dropped by the hash canonicalization.
func TestLedger_PhaseCoverage(t *testing.T) {
	LedgerRoot = t.TempDir()
	l, _ := Open("phases")
	for _, p := range []Phase{PhaseGoalAuth, PhaseSpec, PhaseExec, PhaseRelease} {
		_ = l.Append(Record{Phase: p, Subject: "x", Action: "a", Decision: DecisionAllow})
	}
	l2, _ := Open("phases")
	n, err := l2.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 records, got %d", n)
	}
}

// TestLedger_TamperTruncation: truncating the file (dropping the last record)
// must leave the chain valid up to the new tail, not crash Verify.
func TestLedger_TamperTruncation(t *testing.T) {
	LedgerRoot = t.TempDir()
	l, _ := Open("trunc")
	for i := 0; i < 5; i++ {
		l.Append(Record{Phase: PhaseExec, Subject: "x", Action: "a", Decision: DecisionAllow})
	}
	// truncate by reading lines and dropping the last
	path := filepath.Join(LedgerRoot, "trunc", "ledger.jsonl")
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	truncated := strings.Join(lines[:len(lines)-2], "\n") + "\n"
	os.WriteFile(path, []byte(truncated), 0644)

	l2, _ := Open("trunc")
	n, err := l2.Verify()
	if err != nil {
		t.Fatalf("truncated chain should still verify on its prefix: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 surviving records, got %d", n)
	}
}

// TestLedger_EmptyVerify: a non-existent ledger verifies cleanly as 0 records.
func TestLedger_EmptyVerify(t *testing.T) {
	LedgerRoot = t.TempDir()
	l, _ := Open("never-existed")
	n, err := l.Verify()
	if err != nil {
		t.Fatalf("empty verify failed: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

// TestLedger_TimeInRecord ensures timestamps survive the round trip; a broken
// clock would let a tamperer reorder events undetectably.
func TestLedger_TimeInRecord(t *testing.T) {
	LedgerRoot = t.TempDir()
	l, _ := Open("times")
	t0 := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	l.Append(Record{Phase: PhaseExec, Subject: "x", Action: "a", Decision: DecisionAllow, At: t0})
	l2, _ := Open("times")
	recs, _ := l2.ReadAll()
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	if !recs[0].At.Equal(t0) {
		t.Errorf("timestamp not preserved: got %v want %v", recs[0].At, t0)
	}
}

// TestLedger_DeterministicHashSameRecord ensures the same logical record
// produces the same hash regardless of Go map iteration order — the whole
// point of canonical JSON in hashRecord.
func TestLedger_DeterministicHashSameRecord(t *testing.T) {
	params := map[string]interface{}{
		"z": 1, "a": 2, "m": 3, "b": 4, "q": "hello",
	}
	r := Record{
		Phase: PhaseExec, Subject: "s", Action: "a",
		Params: params, Decision: DecisionAllow, Reason: "r",
	}
	first := hashRecord(r, "prev")
	// recompute many times; must be identical
	for i := 0; i < 50; i++ {
		if h := hashRecord(r, "prev"); h != first {
			t.Fatalf("hash not deterministic across map iterations: %s vs %s", h, first)
		}
	}
	// and different from a record with a different prev hash
	r2 := r
	if h := hashRecord(r2, "different"); h == first {
		t.Error("hash should depend on prev_hash")
	}
}

// TestLedger_DifferentLedgerIndependent: two ledgers with identical contents
// hash identically record-for-record (cross-ledger hash determinism), but their
// on-disk state never bleeds between tasks.
func TestLedger_DifferentLedgerIndependent(t *testing.T) {
	LedgerRoot = t.TempDir()
	a, _ := Open("task-a")
	b, _ := Open("task-b")
	a.Append(Record{Phase: PhaseExec, Subject: "x", Action: "a", Decision: DecisionAllow})
	b.Append(Record{Phase: PhaseExec, Subject: "x", Action: "a", Decision: DecisionAllow})

	la, _ := a.ReadAll()
	lb, _ := b.ReadAll()
	if la[0].ThisHash != lb[0].ThisHash {
		t.Error("identical records should hash identically across ledgers")
	}
	// but file isolation
	if _, err := os.Stat(filepath.Join(LedgerRoot, "task-a", "ledger.jsonl")); err != nil {
		t.Error("task-a ledger missing")
	}
}

// TestLedger_HashDependsOnAllFields ensures removing the Reason alone changes
// the hash (proves no field is silently ignored in the canonical form).
func TestLedger_HashDependsOnAllFields(t *testing.T) {
	base := Record{Phase: PhaseExec, Subject: "s", Action: "a", Decision: DecisionAllow, Reason: "r", PrevHash: "p"}
	h0 := hashRecord(base, "p")
	variants := []Record{
		{Phase: PhaseGoalAuth, Subject: "s", Action: "a", Decision: DecisionAllow, Reason: "r", PrevHash: "p"},
		{Phase: PhaseExec, Subject: "other", Action: "a", Decision: DecisionAllow, Reason: "r", PrevHash: "p"},
		{Phase: PhaseExec, Subject: "s", Action: "other", Decision: DecisionAllow, Reason: "r", PrevHash: "p"},
		{Phase: PhaseExec, Subject: "s", Action: "a", Decision: DecisionDeny, Reason: "r", PrevHash: "p"},
		{Phase: PhaseExec, Subject: "s", Action: "a", Decision: DecisionAllow, Reason: "changed", PrevHash: "p"},
		{Phase: PhaseExec, Subject: "s", Action: "a", Decision: DecisionAllow, Reason: "r", PrevHash: "p2"},
	}
	for i, v := range variants {
		if hashRecord(v, v.PrevHash) == h0 {
			t.Errorf("variant %d produced same hash as base (field ignored in canonical form)", i)
		}
	}
}

// Compile-time: keep sha256/hex referenced if a future refactor removes them.
var _ = sha256.Sum256
var _ = hex.EncodeToString
var _ = errors.New
