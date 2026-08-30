package audit

import (
	"os"
	"strings"
	"testing"
)

func TestSignerRoundTripAndTamper(t *testing.T) {
	s, err := LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sig := s.Sign("hash-1")
	if !s.Verify("hash-1", sig) {
		t.Fatal("valid signature must verify")
	}
	if s.Verify("hash-2", sig) {
		t.Fatal("signature over a different hash must fail")
	}
	if s.Verify("hash-1", "bogus") {
		t.Fatal("garbage signature must fail")
	}
	var nilSigner *Signer
	if !nilSigner.Verify("h", "") {
		t.Fatal("nil signer treats unsigned as valid")
	}
}

func TestLedgerSigningEndToEnd(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PVM_AUDIT_SIGNING", "1")
	oldLedgerRoot := LedgerRoot
	LedgerRoot = root
	t.Cleanup(func() { LedgerRoot = oldLedgerRoot })
	// Bypass the process-wide cache with a direct signer load.
	s, err := LoadOrCreateSigner(root)
	if err != nil {
		t.Fatal(err)
	}
	signerMu.Lock()
	signerCache[root] = s
	signerMu.Unlock()
	t.Cleanup(func() {
		signerMu.Lock()
		delete(signerCache, root)
		signerMu.Unlock()
	})

	l, err := Open("t-sign")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Append(Record{Phase: PhaseExec, Subject: "agent", Action: "op", Decision: DecisionAllow}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := l.Verify()
	if err != nil || n != 3 {
		t.Fatalf("signed ledger must verify: n=%d err=%v", n, err)
	}

	// Tamper: flip a decision in place. Verify must fail (chain or sig).
	raw, _ := os.ReadFile(l.path)
	tampered := strings.Replace(string(raw), "allow", "deny", 1)
	if werr := os.WriteFile(l.path, []byte(tampered), 0o600); werr != nil {
		t.Fatal(werr)
	}
	if _, err := l.Verify(); err == nil {
		t.Fatal("tampered signed ledger must fail verification")
	}
}

func TestSignerForRootOffByDefault(t *testing.T) {
	t.Setenv("PVM_AUDIT_SIGNING", "")
	root := t.TempDir()
	signerMu.Lock()
	delete(signerCache, root)
	signerMu.Unlock()
	if s := SignerForRoot(root); s != nil {
		t.Fatal("signing must stay off without env or key")
	}
}
