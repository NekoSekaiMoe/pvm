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
					Action:   fmt.Sprintf("call-%d-%d", id, i),
					Params:   map[string]interface{}{"g": id, "i": i},
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
	if err == nil {
		t.Fatal("expected truncation detection error, got nil")
	}
	if !strings.Contains(err.Error(), "ledger truncated") {
		t.Errorf("unexpected error: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 surviving records reported, got %d", n)
	}
}

// TestLedger_TruncationWithoutHeadSkipped: a ledger that never had a head
// watermark (legacy data) must still verify on its surviving prefix.
func TestLedger_TruncationWithoutHeadSkipped(t *testing.T) {
	LedgerRoot = t.TempDir()
	l, _ := Open("legacy")
	for i := 0; i < 3; i++ {
		l.Append(Record{Phase: PhaseExec, Subject: "x", Action: "a", Decision: DecisionAllow})
	}
	path := filepath.Join(LedgerRoot, "legacy", "ledger.jsonl")
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	os.WriteFile(path, []byte(lines[0]+"\n"), 0644)
	// simulate legacy data: no head file
	os.Remove(filepath.Join(LedgerRoot, "legacy", "head"))

	l2, _ := Open("legacy")
	n, err := l2.Verify()
	if err != nil {
		t.Fatalf("legacy truncated chain should verify on its prefix: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 surviving record, got %d", n)
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

// TestLedger_DifferentLedgerIndependent: two ledgers with identical record
// CONTENT hash identically when the content includes the SAME task. Because
// hashRecord now binds the Task field into the digest (per the security
// review), records that differ only in their task id correctly hash
// differently — so this test uses a shared task id to exercise the
// cross-ledger determinism property, then separately checks file isolation.
func TestLedger_DifferentLedgerIndependent(t *testing.T) {
	LedgerRoot = t.TempDir()
	a, _ := Open("shared-task")
	b, _ := Open("shared-task")
	a.Append(Record{Phase: PhaseExec, Subject: "x", Action: "a", Decision: DecisionAllow})
	b.Append(Record{Phase: PhaseExec, Subject: "x", Action: "a", Decision: DecisionAllow})

	la, _ := a.ReadAll()
	lb, _ := b.ReadAll()
	if la[0].ThisHash != lb[0].ThisHash {
		t.Error("identical records should hash identically across ledgers")
	}
	// Different task ids MUST now hash differently (Task is part of the digest).
	x, _ := Open("task-x")
	y, _ := Open("task-y")
	x.Append(Record{Phase: PhaseExec, Subject: "s", Action: "a", Decision: DecisionAllow})
	y.Append(Record{Phase: PhaseExec, Subject: "s", Action: "a", Decision: DecisionAllow})
	rx, _ := x.ReadAll()
	ry, _ := y.ReadAll()
	if rx[0].ThisHash == ry[0].ThisHash {
		t.Error("records with different task ids must hash differently (Task is bound)")
	}
	// File isolation: each task's ledger lives under its own dir.
	if _, err := os.Stat(filepath.Join(LedgerRoot, "task-x", "ledger.jsonl")); err != nil {
		t.Error("task-x ledger missing")
	}
	if _, err := os.Stat(filepath.Join(LedgerRoot, "task-y", "ledger.jsonl")); err != nil {
		t.Error("task-y ledger missing")
	}
}

// TestLedger_HashDependsOnAllFields ensures removing/changing ANY single
// field changes the hash. After the security review, Seq/At/Task/Tenant are
// part of the digest too, so this test now covers variants for each of them.
func TestLedger_HashDependsOnAllFields(t *testing.T) {
	base := Record{
		Seq: 7, At: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Task: "task", Tenant: "tenant",
		Phase: PhaseExec, Subject: "s", Action: "a",
		Decision: DecisionAllow, Reason: "r", PrevHash: "p",
	}
	h0 := hashRecord(base, "p")
	variants := []Record{
		{Seq: 8, At: base.At, Task: base.Task, Tenant: base.Tenant, Phase: base.Phase, Subject: base.Subject, Action: base.Action, Decision: base.Decision, Reason: base.Reason, PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At.Add(time.Second), Task: base.Task, Tenant: base.Tenant, Phase: base.Phase, Subject: base.Subject, Action: base.Action, Decision: base.Decision, Reason: base.Reason, PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At, Task: "other-task", Tenant: base.Tenant, Phase: base.Phase, Subject: base.Subject, Action: base.Action, Decision: base.Decision, Reason: base.Reason, PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At, Task: base.Task, Tenant: "other-tenant", Phase: base.Phase, Subject: base.Subject, Action: base.Action, Decision: base.Decision, Reason: base.Reason, PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At, Task: base.Task, Tenant: base.Tenant, Phase: PhaseGoalAuth, Subject: base.Subject, Action: base.Action, Decision: base.Decision, Reason: base.Reason, PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At, Task: base.Task, Tenant: base.Tenant, Phase: base.Phase, Subject: "other", Action: base.Action, Decision: base.Decision, Reason: base.Reason, PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At, Task: base.Task, Tenant: base.Tenant, Phase: base.Phase, Subject: base.Subject, Action: "other", Decision: base.Decision, Reason: base.Reason, PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At, Task: base.Task, Tenant: base.Tenant, Phase: base.Phase, Subject: base.Subject, Action: base.Action, Decision: DecisionDeny, Reason: base.Reason, PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At, Task: base.Task, Tenant: base.Tenant, Phase: base.Phase, Subject: base.Subject, Action: base.Action, Decision: base.Decision, Reason: "changed", PrevHash: base.PrevHash},
		{Seq: base.Seq, At: base.At, Task: base.Task, Tenant: base.Tenant, Phase: base.Phase, Subject: base.Subject, Action: base.Action, Decision: base.Decision, Reason: base.Reason, PrevHash: "p2"},
	}
	for i, v := range variants {
		if hashRecord(v, v.PrevHash) == h0 {
			t.Errorf("variant %d produced same hash as base (field ignored in canonical form)", i)
		}
	}
}

// TestLedger_IncrementalTailMatchesFullScan is the regression test for the
// O(n²) append path: after many appends on a long-lived Ledger handle, the
// incrementally-maintained tail (seq/lastHash) must equal what a fresh full
// scan reports, and cross-process-style appends through a SECOND handle must
// be picked up by the first handle's locked refresh.
func TestLedger_IncrementalTailMatchesFullScan(t *testing.T) {
	LedgerRoot = t.TempDir()
	l, _ := Open("incr")
	for i := 0; i < 200; i++ {
		if err := l.Append(Record{Phase: PhaseExec, Subject: "x", Action: fmt.Sprint(i), Decision: DecisionAllow}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// A second handle simulates another process appending.
	l2, _ := Open("incr")
	if err := l2.Append(Record{Phase: PhaseExec, Subject: "peer", Action: "peer-write", Decision: DecisionAllow}); err != nil {
		t.Fatalf("peer append: %v", err)
	}
	// The first handle must pick up the peer's record under its lock.
	if err := l.Append(Record{Phase: PhaseExec, Subject: "x", Action: "after-peer", Decision: DecisionAllow}); err != nil {
		t.Fatalf("append after peer: %v", err)
	}

	n, err := l.Verify()
	if err != nil {
		t.Fatalf("chain broken after mixed incremental/full refreshes: %v", err)
	}
	if n != 202 {
		t.Errorf("verified %d records, want 202", n)
	}
	recs, err := l.ReadAll()
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	last := recs[len(recs)-1]
	l.mu.Lock()
	gotSeq, gotHash := l.seq, l.lastHash
	l.mu.Unlock()
	if gotSeq != last.Seq || gotHash != last.ThisHash {
		t.Errorf("incremental tail (seq=%d) out of sync with disk (seq=%d)", gotSeq, last.Seq)
	}
}

// TestLedger_FilePermissions pins the evidence-file modes: task dir 0700,
// ledger and head 0600 — including files that already existed with looser
// modes from older versions.
func TestLedger_FilePermissions(t *testing.T) {
	LedgerRoot = t.TempDir()
	// Pre-create with loose modes like an older deployment would have.
	dir := filepath.Join(LedgerRoot, "perm")
	os.MkdirAll(dir, 0755)
	os.WriteFile(filepath.Join(dir, "ledger.jsonl"), nil, 0644)
	os.WriteFile(filepath.Join(dir, "head"), nil, 0644)

	l, err := Open("perm")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := l.Append(Record{Phase: PhaseExec, Subject: "x", Action: "a", Decision: DecisionAllow}); err != nil {
		t.Fatalf("append: %v", err)
	}
	for _, tc := range []struct {
		path string
		want os.FileMode
	}{{dir, 0700}, {filepath.Join(dir, "ledger.jsonl"), 0600}, {filepath.Join(dir, "head"), 0600}} {
		fi, err := os.Stat(tc.path)
		if err != nil {
			t.Fatalf("stat %s: %v", tc.path, err)
		}
		if got := fi.Mode().Perm(); got != tc.want {
			t.Errorf("%s mode = %o, want %o", tc.path, got, tc.want)
		}
	}
}

// TestOpen_InvalidTaskIDs pins the defense-in-depth id validation: ids that
// would escape LedgerRoot or smuggle odd characters are rejected.
func TestOpen_InvalidTaskIDs(t *testing.T) {
	LedgerRoot = t.TempDir()
	cases := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "empty id", id: "", wantErr: true},
		{name: "parent escape", id: "../escape", wantErr: true},
		{name: "slash separated", id: "a/b", wantErr: true},
		{name: "dot character", id: "a.b", wantErr: true},
		{name: "embedded space", id: "has space", wantErr: true},
		{name: "too long (129 chars)", id: strings.Repeat("a", 129), wantErr: true},
		// Boundary: exactly 128 chars is fine.
		{name: "boundary 128 chars", id: strings.Repeat("a", 128), wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(tc.id)
			if tc.wantErr && err == nil {
				t.Errorf("Open(%q) accepted an invalid task id", tc.id)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Open(%q) rejected a valid task id: %v", tc.id, err)
			}
		})
	}
}

// Compile-time: keep sha256/hex referenced if a future refactor removes them.
var _ = sha256.Sum256
var _ = hex.EncodeToString
var _ = errors.New
