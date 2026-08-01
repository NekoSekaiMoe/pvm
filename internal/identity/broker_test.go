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
	b := NewBroker(nil, StaticStore{"repo:read": "supersecret"}, tmpLedger(t), time.Minute)
	tok, err := b.Mint("alice", "eng", []string{"repo:read"}, time.Minute)
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
	b := NewBroker([]byte("k"), nil, tmpLedger(t), time.Minute)
	tok, _ := b.Mint("alice", "eng", nil, time.Minute)
	// flip one char in the payload
	tampered := tok[:5] + "X" + tok[6:]
	if _, err := b.Validate(tampered); err == nil {
		t.Fatal("expected signature error on tampered token")
	}
}

func TestValidate_Expired(t *testing.T) {
	b := NewBroker(nil, nil, tmpLedger(t), time.Millisecond)
	tok, _ := b.Mint("alice", "eng", nil, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, err := b.Validate(tok); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	b := NewBroker(nil, nil, tmpLedger(t), time.Hour)
	tok, _ := b.Mint("alice", "eng", nil, time.Hour)
	parsed, _ := b.Validate(tok)
	b.Revoke(parsed.ID)
	if _, err := b.Validate(tok); err != ErrRevoked {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

func TestRequireScope(t *testing.T) {
	b := NewBroker(nil, StaticStore{}, tmpLedger(t), time.Hour)
	tok, _ := b.Mint("alice", "eng", []string{"repo:read", "db:read"}, time.Hour)
	if _, err := b.RequireScope(tok, "repo:read"); err != nil {
		t.Errorf("should have repo:read: %v", err)
	}
	_, err := b.RequireScope(tok, "repo:write")
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected scope-missing error, got %v", err)
	}
}

func TestSecretsNeverInToken(t *testing.T) {
	store := StaticStore{"repo:read": "leak-me-not"}
	b := NewBroker(nil, store, tmpLedger(t), time.Hour)
	tok, _ := b.Mint("alice", "eng", []string{"repo:read"}, time.Hour)
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
