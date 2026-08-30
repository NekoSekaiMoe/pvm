package identity

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeyPersistenceAcrossBrokers(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")

	key1, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(key1) != string(key2) {
		t.Fatal("key must be stable across loads")
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file must be 0600, got %v", fi.Mode().Perm())
	}
}

func TestTokenSurvivesRestartWithPersistentKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	revPath := filepath.Join(dir, "revocations.json")

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	b1, err := NewBroker(key, StaticStore{}, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := b1.PersistRevocations(revPath); err != nil {
		t.Fatal(err)
	}
	tok, err := b1.Mint("agent", "t", "task-1", []string{"repo:read"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	revokedTok, _ := b1.Mint("agent", "t", "task-1", []string{"repo:read"}, time.Minute)
	b1.Revoke(idOf(t, revokedTok))
	b1.RevokeAllForTask("task-2")

	// "Restart": fresh broker, same key file + revocation file.
	b2, err := NewBroker(key, StaticStore{}, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.PersistRevocations(revPath); err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Validate(tok); err != nil {
		t.Fatalf("valid token must survive restart: %v", err)
	}
	if _, err := b2.Validate(revokedTok); err != ErrRevoked {
		t.Fatalf("revoked token must stay revoked across restart, got %v", err)
	}
}

func TestRefreshRotatesAndRevokes(t *testing.T) {
	b, _ := NewBroker(nil, StaticStore{}, nil, time.Minute)
	tok, err := b.Mint("agent", "t", "task-3", []string{"repo:read", "deploy:prod"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := b.Refresh(tok, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Validate(tok); err != ErrRevoked {
		t.Fatalf("old token must be revoked after refresh, got %v", err)
	}
	ft, err := b.RequireScope(fresh, "repo:read", "deploy:prod")
	if err != nil {
		t.Fatalf("refreshed token must carry scopes: %v", err)
	}
	if ft.Caller != "agent" {
		t.Fatalf("refresh must preserve caller, got %q", ft.Caller)
	}
}

// idOf extracts the token id (payload.ID) from a token string.
func idOf(t *testing.T, tokStr string) string {
	t.Helper()
	parts := splitToken(tokStr)
	var tok Token
	if err := jsonUnmarshal(parts, &tok); err != nil {
		t.Fatal(err)
	}
	return tok.ID
}

func TestTaskWideRevocationGate(t *testing.T) {
	b, _ := NewBroker(nil, StaticStore{}, nil, time.Minute)
	tok, _ := b.Mint("agent", "t", "task-4", []string{"repo:read"}, time.Minute)
	b.RevokeAllForTask("task-4")
	if _, err := b.Validate(tok); err != ErrRevoked {
		t.Fatalf("task revocation must deny member token, got %v", err)
	}
}

func splitToken(tokStr string) []byte {
	parts := strings.SplitN(tokStr, ".", 2)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	return raw
}

func jsonUnmarshal(raw []byte, v interface{}) error { return json.Unmarshal(raw, v) }
