package identity

import (
	"strings"
	"testing"
	"time"

	"uml-container/internal/audit"
)

func tmpLedger(t *testing.T) *audit.Ledger {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, err := audit.Open("idtest")
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	return l
}

func TestMintValidate_RoundTrip(t *testing.T) {
	b, err := NewBroker(nil, StaticStore{"repo:read": "supersecret"}, tmpLedger(t), time.Minute)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	tok, err := b.Mint("alice", "eng", "task-1", []string{"repo:read"}, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parsed, err := b.Validate(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if parsed.Caller != "alice" || len(parsed.Scope) != 1 || parsed.Scope[0] != "repo:read" {
		t.Errorf("parsed token wrong: %+v", parsed)
	}
}

func TestValidate_RejectsTampered(t *testing.T) {
	b, err := NewBroker([]byte("k"), nil, tmpLedger(t), time.Minute)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	tok, _ := b.Mint("alice", "eng", "task-1", nil, time.Minute)
	// flip one char in the payload
	tampered := tok[:5] + "X" + tok[6:]
	if _, err := b.Validate(tampered); err == nil {
		t.Fatal("expected signature error on tampered token")
	}
}

func TestValidate_Expired(t *testing.T) {
	b, err := NewBroker(nil, nil, tmpLedger(t), time.Millisecond)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	tok, _ := b.Mint("alice", "eng", "task-1", nil, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, err := b.Validate(tok); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	b, err := NewBroker(nil, nil, tmpLedger(t), time.Hour)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	tok, _ := b.Mint("alice", "eng", "task-1", nil, time.Hour)
	parsed, _ := b.Validate(tok)
	b.Revoke(parsed.ID)
	if _, err := b.Validate(tok); err != ErrRevoked {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

func TestRequireScope(t *testing.T) {
	b, err := NewBroker(nil, StaticStore{}, tmpLedger(t), time.Hour)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	tok, _ := b.Mint("alice", "eng", "task-1", []string{"repo:read", "db:read"}, time.Hour)
	if _, err := b.RequireScope(tok, "repo:read"); err != nil {
		t.Errorf("should have repo:read: %v", err)
	}
	_, err = b.RequireScope(tok, "repo:write")
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected scope-missing error, got %v", err)
	}
}

func TestSecretsNeverInToken(t *testing.T) {
	store := StaticStore{"repo:read": "leak-me-not"}
	b, err := NewBroker(nil, store, tmpLedger(t), time.Hour)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	tok, _ := b.Mint("alice", "eng", "task-1", []string{"repo:read"}, time.Hour)
	// the token string itself must not contain the secret
	if strings.Contains(tok, "leak-me-not") {
		t.Fatal("LONG-LIVED SECRET LEAKED INTO TOKEN")
	}
	// but the host-side lookup must still work
	v, ok := b.LookupSecret("repo:read")
	if !ok || v != "leak-me-not" {
		t.Errorf("host-side lookup failed: %q ok=%v", v, ok)
	}
}

// TestRevokeAllForTask_RevokesEveryMintedToken is the regression test for the
// P0 incident-response gap: RevokeAllForTask must actually invalidate every
// token minted for the task, not just append an audit row. The previous impl
// returned 0 without touching the revocation set, so an incident response
// believed it had cut off access while every token stayed valid.
func TestRevokeAllForTask_RevokesEveryMintedToken(t *testing.T) {
	b, err := NewBroker(nil, nil, tmpLedger(t), time.Hour)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	// Mint three tokens for task-A and one for task-B.
	var toksA [3]string
	for i := range toksA {
		tok, err := b.Mint("alice", "eng", "task-A", []string{"repo:read"}, time.Hour)
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		toksA[i] = tok
	}
	tokB, err := b.Mint("bob", "eng", "task-B", []string{"repo:read"}, time.Hour)
	if err != nil {
		t.Fatalf("mint task-B: %v", err)
	}

	// All tokens must be valid up front.
	for i, tok := range toksA {
		if _, err := b.Validate(tok); err != nil {
			t.Fatalf("task-A token %d not valid before revoke: %v", i, err)
		}
	}

	revoked := b.RevokeAllForTask("task-A")
	if revoked != len(toksA) {
		t.Fatalf("RevokeAllForTask revoked %d, want %d", revoked, len(toksA))
	}

	// Every task-A token must now be rejected with ErrRevoked.
	for i, tok := range toksA {
		if _, err := b.Validate(tok); err != ErrRevoked {
			t.Errorf("task-A token %d still usable after revoke: err=%v", i, err)
		}
	}
	// task-B's token must be UNAFFECTED (bulk revoke must not be over-broad).
	if _, err := b.Validate(tokB); err != nil {
		t.Errorf("task-B token revoked by a task-A bulk revoke: %v", err)
	}
}

// TestRevokeAllForTask_UnknownTaskIsNoop ensures revoking a task with no live
// tokens is a benign no-op (returns 0, no audit gymnastics).
func TestRevokeAllForTask_UnknownTaskIsNoop(t *testing.T) {
	b, _ := NewBroker(nil, nil, tmpLedger(t), time.Hour)
	if n := b.RevokeAllForTask("never-heard-of"); n != 0 {
		t.Errorf("revoking unknown task revoked %d, want 0", n)
	}
}
