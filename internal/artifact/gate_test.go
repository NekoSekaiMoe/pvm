package artifact

import (
	"strings"
	"testing"

	"uml-container/internal/audit"
)

func tmpLedger(t *testing.T) *audit.Ledger {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("artifact-test")
	return l
}

func TestGate_PassesCleanBundle(t *testing.T) {
	g := NewGate(tmpLedger(t))
	b := &Bundle{
		TaskID:    "t1",
		Diff:      "--- a\n+++ b\n@@\n+print('hello')\n",
		Files:     map[string][]byte{"out/diff.patch": []byte("clean")},
		ClaimedOK: true,
	}
	v := g.Verify(b)
	if !v.Passed {
		t.Errorf("expected pass, got reasons: %v", v.Reasons)
	}
	if v.Hash == "" {
		t.Error("hash not bound")
	}
}

func TestSecretScan_BlocksAWSKey(t *testing.T) {
	g := NewGate(tmpLedger(t))
	b := &Bundle{
		TaskID: "t2",
		Diff:   "AKIA" + "IOSFODNN7EXAMPLE", // well-known AWS docs example key
	}
	v := g.Verify(b)
	if v.Passed {
		t.Fatal("expected secret scan to block AWS key")
	}
	if !containsAny(v.Reasons, "secret pattern") {
		t.Errorf("expected secret-pattern reason, got %v", v.Reasons)
	}
}

func TestSecretScan_BlocksPrivateKey(t *testing.T) {
	g := NewGate(tmpLedger(t))
	b := &Bundle{
		TaskID: "t3",
		Files: map[string][]byte{
			"id_rsa": []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE"),
		},
	}
	v := g.Verify(b)
	if v.Passed {
		t.Fatal("expected private-key block")
	}
}

func TestHash_StableAcrossIterations(t *testing.T) {
	b := &Bundle{
		TaskID: "t4",
		Files: map[string][]byte{
			"a": []byte("1"),
			"b": []byte("2"),
			"c": []byte("3"),
		},
	}
	h1 := hashBundle(b)
	for i := 0; i < 20; i++ {
		if hashBundle(b) != h1 {
			t.Fatal("hashBundle not stable across map iterations")
		}
	}
}

func TestRelease_RejectedBlocksRelease(t *testing.T) {
	called := false
	rs := &ReleaseService{
		Gate: NewGate(tmpLedger(t)),
		Release: func(*Bundle, *Verdict) error {
			called = true
			return nil
		},
	}
	b := &Bundle{TaskID: "t5", Diff: "ghp_" + strings.Repeat("a", 36)} // GitHub token
	if err := rs.Submit(b); err == nil {
		t.Fatal("expected rejection")
	}
	if called {
		t.Fatal("Release must NOT be called when gate fails")
	}
}

func TestRelease_PassCallsRelease(t *testing.T) {
	called := false
	rs := &ReleaseService{
		Gate: NewGate(tmpLedger(t)),
		Release: func(*Bundle, *Verdict) error {
			called = true
			return nil
		},
	}
	b := &Bundle{TaskID: "t6", Diff: "clean", ClaimedOK: true}
	if err := rs.Submit(b); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !called {
		t.Error("Release should be called on pass")
	}
}

func containsAny(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// TestSecretScan_BlocksSecretInTrace is the regression test for the
// missed-corpus bug: Trace used to be excluded from the scan entirely, so an
// API key echoed into a tool-call summary would pass the gate. Now Trace is
// part of the corpus.
func TestSecretScan_BlocksSecretInTrace(t *testing.T) {
	v := SecretScanVerifier{}
	b := &Bundle{
		Trace: []string{"ran gh tool with ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd"},
	}
	ok, reason := v.Verify(b)
	if ok {
		t.Fatalf("expected secret in Trace to fail the scan; reason=%q", reason)
	}
	if !strings.Contains(reason, "secret pattern") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

// TestHash_BindsContentNotLength verifies that replacing a diff with a
// same-length forgery changes the hash. Pre-fix, hashBundle only wrote
// len(Diff)/len(BuildLog)/len(Trace) — a same-length swap was undetectable.
func TestHash_BindsContentNotLength(t *testing.T) {
	b1 := &Bundle{TaskID: "t", Diff: "AAAA", BuildLog: "BBBB", Trace: []string{"CCCC"}}
	b2 := &Bundle{TaskID: "t", Diff: "XXXX", BuildLog: "YYYY", Trace: []string{"ZZZZ"}} // same lengths
	if hashBundle(b1) == hashBundle(b2) {
		t.Error("same-length different content produced identical hash (content not bound)")
	}
}

// TestHash_BindsEachTraceElement ensures multiple trace elements each
// contribute independently to the digest, including the boundary between
// one element and two elements whose concatenation is identical: a single
// "ab" must hash differently than two elements "a"+"b" (otherwise an
// attacker could split/merge trace entries to collide digests).
func TestHash_BindsEachTraceElement(t *testing.T) {
	b1 := &Bundle{TaskID: "t", Trace: []string{"a", "b"}}
	b2 := &Bundle{TaskID: "t", Trace: []string{"a", "c"}}
	if hashBundle(b1) == hashBundle(b2) {
		t.Error("changing a trace element did not change the hash")
	}
	// Element-boundary regression: ["ab"] must not collide with ["a","b"].
	merged := &Bundle{TaskID: "t", Trace: []string{"ab"}}
	split := &Bundle{TaskID: "t", Trace: []string{"a", "b"}}
	if hashBundle(merged) == hashBundle(split) {
		t.Error("trace element boundary is not bound: [\"ab\"] collided with [\"a\",\"b\"]")
	}
}
