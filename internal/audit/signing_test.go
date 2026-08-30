package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

// TestLoadOrCreateSigner_ConcurrentInit races 16 first-boot signers against
// one fresh directory: every goroutine must succeed and every public key
// must agree (no overwrite split-brain). Guards the O_EXCL race fix — the
// old single-retry recursion died on a winner key read between O_EXCL
// create and the finished PEM write.
func TestLoadOrCreateSigner_ConcurrentInit(t *testing.T) {
	dir := t.TempDir()
	const n = 16
	pubs := make([]ed25519.PublicKey, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			s, err := LoadOrCreateSigner(dir)
			errs[i] = err
			if s != nil {
				pubs[i] = s.pub
			}
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d failed: %v", i, errs[i])
		}
		if !pubs[i].Equal(pubs[0]) {
			t.Fatalf("goroutine %d public key diverges from goroutine 0's", i)
		}
	}
}

// TestAdoptWinnerSigner_WaitsForWinnerWrite pins the bounded-retry fix: the
// race loser may read the winner's key between O_EXCL create and the
// finished PEM write (empty/half-written) — adoption must retry until the
// PEM parses instead of returning malformed.
func TestAdoptWinnerSigner_WaitsForWinnerWrite(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, signingKeyFile)
	// Simulate the winner: file exists (created via O_EXCL) but the PEM
	// body lands only 60ms later.
	if err := os.WriteFile(keyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(60 * time.Millisecond)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv})
		_ = os.WriteFile(keyPath, pemBytes, 0o600)
	}()

	s, err := adoptWinnerSigner(keyPath)
	if err != nil {
		t.Fatalf("adoptWinnerSigner should wait out the half-written key: %v", err)
	}
	if !s.pub.Equal(pub) {
		t.Fatal("adopted signer must carry the winner's public key")
	}
	sig := s.Sign("payload")
	if !s.Verify("payload", sig) {
		t.Fatal("adopted signer must verify its own signature")
	}
}

// TestAdoptWinnerSigner_BoundedExhaustion: a permanently malformed key must
// fail after the bounded attempts (no infinite loop / recursion), with the
// attempt count surfaced in the error.
func TestAdoptWinnerSigner_BoundedExhaustion(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, signingKeyFile)
	if err := os.WriteFile(keyPath, []byte("not a pem block"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := adoptWinnerSigner(keyPath)
	if err == nil {
		t.Fatal("permanently malformed key must eventually error")
	}
	if !strings.Contains(err.Error(), "10") {
		t.Fatalf("error should mention attempt count, got: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("retry budget exceeded: %v", d)
	}
}

// TestLoadOrCreateSigner_RoundTrip: a created signer persists and reloads
// byte-identically through loadSignerFile.
func TestLoadOrCreateSigner_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s1, err := LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1.pub, s2.pub) {
		t.Fatal("reload must return the same key pair")
	}
	// Corrupt keys must surface as malformed, not be regenerated.
	if err := os.WriteFile(filepath.Join(dir, signingKeyFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSigner(dir); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("corrupt key must fail as malformed, got %v", err)
	}
}
