package securitytest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uml-container/internal/audit"
)

// ATTACK 11: plant secrets into Params and Reason of a ledger record. The
// on-disk bytes of the append-only ledger MUST NOT contain any plaintext
// secret (they are hashed into the chain forever), and the redacted chain
// MUST still Verify.
func TestAttack_SecretLeakIntoLedgerBytes(t *testing.T) {
	setupRoots(t)
	audit.SetRedactionEnabled(true) // paranoia: other attacks may not toggle it

	ghp := "ghp_" + strings.Repeat("E", 40)
	akia := "AKIA" + strings.Repeat("F", 16)
	bearer := "Bearer " + strings.Repeat("u", 30)
	password := "sup3rs3cr3tpw"

	l, err := audit.Open("sec-redact")
	if err != nil {
		t.Fatal(err)
	}
	err = l.Append(audit.Record{
		Phase:   audit.PhaseExec,
		Subject: "agent",
		Action:  "tool:http",
		Params: map[string]interface{}{
			"url":        "https://hooks.example.com/x?token=" + ghp,
			"api_token":  akia, // secret-named key: must be DROPPED
			"nested":     map[string]interface{}{"password": password},
			"note":       "auth used " + bearer,
			"benign_key": "keyboard-layout", // contains "key": dropped too (deny-by-default)
			"path":       "/tmp/ok",
		},
		Decision: audit.DecisionAllow,
		Reason:   "upstream 401 presented " + akia,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(audit.LedgerRoot, "sec-redact", "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, plant := range []string{ghp, akia, bearer, password} {
		if bytes.Contains(raw, []byte(plant)) {
			t.Errorf("SECURITY: plaintext secret %q found in ledger bytes", plant[:12]+"...")
		}
	}
	if !bytes.Contains(raw, []byte(audit.RedactedPlaceholder)) {
		t.Error("expected [REDACTED] markers in the ledger record")
	}
	if !bytes.Contains(raw, []byte("/tmp/ok")) {
		t.Error("benign param value was lost by over-redaction")
	}

	// Redaction happened BEFORE hashing, so the chain must verify.
	if n, err := l.Verify(); err != nil {
		t.Fatalf("SECURITY: redacted ledger failed Verify after %d records: %v", n, err)
	}
}

// ATTACK 11b: the escape hatch — audit.WithRedactor(nil) disables scrubbing
// (used by tests/forensics that must reproduce byte-exact historical writes).
// This documents that ONLY an explicit opt-out stores plaintext.
func TestAttack_RedactorEscapeHatchStoresRaw(t *testing.T) {
	setupRoots(t)
	// The default redactor is a process-global switch; another test in
	// this package may have flipped it off without restoring. Pin it so
	// the "default ledger still scrubs" assertion below holds
	// independently of test ordering — and restore the previous state so
	// this test is not the ordering hazard it fixes.
	previous := audit.RedactionEnabled()
	audit.SetRedactionEnabled(true)
	t.Cleanup(func() { audit.SetRedactionEnabled(previous) })

	secret := "ghp_" + strings.Repeat("0", 40)
	l, err := audit.Open("sec-raw", audit.WithRedactor(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  "agent",
		Action:   "tool:http",
		Decision: audit.DecisionAllow,
		Reason:   "raw reason " + secret,
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(audit.LedgerRoot, "sec-raw", "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(secret)) {
		t.Error("WithRedactor(nil) ledger should store the record byte-exact (escape hatch broken)")
	}
	if _, err := l.Verify(); err != nil {
		t.Fatalf("unredacted ledger must still Verify: %v", err)
	}

	// The DEFAULT redactor is process-wide: a ledger opened without the
	// option in the same run must still scrub even after the escape-hatch
	// ledger exists.
	l2, err := audit.Open("sec-default-after-raw")
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Append(audit.Record{
		Phase: audit.PhaseExec, Subject: "agent", Action: "tool:http",
		Decision: audit.DecisionAllow, Reason: "raw reason " + secret,
	}); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(filepath.Join(audit.LedgerRoot, "sec-default-after-raw", "ledger.jsonl"))
	if bytes.Contains(raw2, []byte(secret)) {
		t.Error("SECURITY: default-opened ledger stored plaintext while a nil-redactor ledger exists")
	}
}
