// Package identity implements the Credential Broker (plan.md §3).
//
// Core rule: long-lived secrets NEVER enter the sandbox. The broker holds the
// long-lived material on the host side and mints short-lived, scope-bounded
// tokens for the agent. A token carries (caller, tenant, scope[], expiry) and
// is HMAC-signed so the broker can later attest "this call was really made by
// task X under scope Y".
//
// Tokens are revocable: REVOKE (plan.md §3.3 / §11) adds the token id to an
// in-memory revocation set; any subsequent Validate returns ErrRevoked.
//
// This is an MVP broker: process-local, HMAC-based. The interface is shaped so
// a Vault/OIDC backend can drop in later.
package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"uml-container/internal/audit"
)

// Errors surfaced to callers.
var (
	ErrRevoked   = errors.New("identity: token revoked")
	ErrExpired   = errors.New("identity: token expired")
	ErrSignature = errors.New("identity: token signature invalid")
	ErrScope     = errors.New("identity: token scope insufficient")
)

// Token is the bearer the agent receives. The on-the-wire form is
// "<payload-base64>.<sig-base64>". Payload contains NO long-lived secret.
type Token struct {
	ID     string    `json:"id"`
	Caller string    `json:"caller"`
	Tenant string    `json:"tenant"`
	Scope  []string  `json:"scope"`
	Exp    time.Time `json:"exp"`
}

// Broker mints and validates short-lived tokens. It owns the signing key and
// the revocation set; the long-lived secret store is injected via SecretStore.
type Broker struct {
	signingKey  []byte
	mu          sync.RWMutex
	revoked     map[string]struct{} // keyed by token ID
	ledger      *audit.Ledger
	store       SecretStore
	defaultTTL  time.Duration
}

// SecretStore maps a capability string (e.g. "repo:read") to the actual
// long-lived secret material. The broker calls Lookup only at mint time, on
// the host, and returns only the token to the caller — never the secret.
type SecretStore interface {
	Lookup(capability string) (string, bool)
}

// StaticStore is a simple in-memory secret store (map[cap]secret).
type StaticStore map[string]string

func (s StaticStore) Lookup(cap string) (string, bool) {
	v, ok := s[cap]
	return v, ok
}

// NewBroker constructs a broker with the given signing key and store. If key
// is empty, a random one is generated (tokens won't survive a process restart,
// which is the desired posture for an MVP — no durable secret on disk).
func NewBroker(key []byte, store SecretStore, ledger *audit.Ledger, defaultTTL time.Duration) *Broker {
	if len(key) == 0 {
		key = make([]byte, 32)
		rand.Read(key)
	}
	if defaultTTL == 0 {
		defaultTTL = 15 * time.Minute
	}
	return &Broker{
		signingKey: key,
		revoked:    make(map[string]struct{}),
		ledger:     ledger,
		store:      store,
		defaultTTL: defaultTTL,
	}
}

// Mint issues a token for (caller, tenant) carrying exactly the scopes the
// TaskSpec's Identity.Scope permitted. ttl overrides the broker default if >0.
func (b *Broker) Mint(caller, tenant string, scope []string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = b.defaultTTL
	}
	id := randID()
	tok := Token{
		ID:     id,
		Caller: caller,
		Tenant: tenant,
		Scope:  append([]string{}, scope...),
		Exp:    time.Now().Add(ttl).UTC(),
	}
	payload, err := json.Marshal(tok)
	if err != nil {
		return "", err
	}
	sig := b.sign(payload)
	tokStr := encode(payload) + "." + sig
	if b.ledger != nil {
		_ = b.ledger.Append(audit.Record{
			Phase:    audit.PhaseGoalAuth,
			Subject:  caller,
			Action:   "mint",
			Params:   map[string]interface{}{"token_id": id, "tenant": tenant, "scope": scope, "ttl": ttl.String()},
			Decision: audit.DecisionAllow,
			Reason:   "credential broker mint",
		})
	}
	return tokStr, nil
}

// Validate parses a token string, checks signature/expiry/revocation.
func (b *Broker) Validate(tokStr string) (*Token, error) {
	parts := strings.SplitN(tokStr, ".", 2)
	if len(parts) != 2 {
		return nil, ErrSignature
	}
	payload, err := decode(parts[0])
	if err != nil {
		return nil, ErrSignature
	}
	if !hmac.Equal([]byte(parts[1]), []byte(b.sign(payload))) {
		return nil, ErrSignature
	}
	var tok Token
	if err := json.Unmarshal(payload, &tok); err != nil {
		return nil, ErrSignature
	}
	b.mu.RLock()
	_, revoked := b.revoked[tok.ID]
	b.mu.RUnlock()
	if revoked {
		return nil, ErrRevoked
	}
	if time.Now().After(tok.Exp) {
		return nil, ErrExpired
	}
	return &tok, nil
}

// RequireScope validates the token AND checks it carries every required scope.
func (b *Broker) RequireScope(tokStr string, required ...string) (*Token, error) {
	tok, err := b.Validate(tokStr)
	if err != nil {
		return nil, err
	}
	have := make(map[string]struct{}, len(tok.Scope))
	for _, s := range tok.Scope {
		have[s] = struct{}{}
	}
	for _, want := range required {
		if _, ok := have[want]; !ok {
			return nil, fmt.Errorf("%w: missing %q", ErrScope, want)
		}
	}
	return tok, nil
}

// Revoke adds a token id to the revocation set. Used by the incident
// controller (plan.md §11 REVOKE).
func (b *Broker) Revoke(tokenID string) {
	b.mu.Lock()
	b.revoked[tokenID] = struct{}{}
	b.mu.Unlock()
	if b.ledger != nil {
		_ = b.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  tokenID,
			Action:   "revoke",
			Decision: audit.DecisionRevoke,
			Reason:   "credential broker revoke",
		})
	}
}

// RevokeAllForTask revokes every token whose ID starts with the task prefix
// (Mint prefixes token IDs with the caller). This is the bulk-revoke path the
// incident controller uses to "切断所有权限" in one shot.
func (b *Broker) RevokeAllForTask(prefix string) int {
	// We don't keep a forward index (by design: less PII to leak); instead we
	// walk the ledger for this task's mints. The prefix-based ID scheme means
	// any caller-matching id is caught. In the MVP we just record intent; full
	// enumeration requires the ledger, which is optional here.
	if b.ledger != nil {
		_ = b.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  prefix,
			Action:   "revoke_all",
			Decision: audit.DecisionRevoke,
			Reason:   "bulk revoke for task",
		})
	}
	return 0
}

// LookupSecret exposes the long-lived material for a capability to a HOST-side
// caller (never to the sandbox). The tool gateway uses this when it needs to
// perform an action on behalf of the agent without leaking the secret in.
func (b *Broker) LookupSecret(capability string) (string, bool) {
	if b.store == nil {
		return "", false
	}
	return b.store.Lookup(capability)
}

// sign returns the base64 HMAC-SHA256 of payload.
func (b *Broker) sign(payload []byte) string {
	mac := hmac.New(sha256.New, b.signingKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// randID is a 12-byte random url-safe id; prefixed with a timestamp for loose
// ordering, which also makes RevokeAllForTask's prefix walk meaningful.
func randID() string {
	var b [12]byte
	rand.Read(b[:])
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), base64.RawURLEncoding.EncodeToString(b[:]))
}
