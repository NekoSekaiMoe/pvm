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
	"log"
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
	signingKey []byte
	mu         sync.RWMutex
	revoked    map[string]struct{} // keyed by token ID
	// activeByTask maps a task id -> set of minted token IDs that are still
	// live. Maintained so RevokeAllForTask can enumerate and revoke without
	// relying on ID prefix matching.
	activeByTask map[string]map[string]struct{}
	ledger       *audit.Ledger
	store        SecretStore
	defaultTTL   time.Duration
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
// which is the desired posture for an MVP — no durable secret on disk). It
// returns an error if the signing key cannot be generated securely.
func NewBroker(key []byte, store SecretStore, ledger *audit.Ledger, defaultTTL time.Duration) (*Broker, error) {
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("identity: generate signing key: %w", err)
		}
	}
	if defaultTTL == 0 {
		defaultTTL = 15 * time.Minute
	}
	return &Broker{
		signingKey:   key,
		revoked:      make(map[string]struct{}),
		activeByTask: make(map[string]map[string]struct{}),
		ledger:       ledger,
		store:        store,
		defaultTTL:   defaultTTL,
	}, nil
}

// Mint issues a token for (caller, tenant) carrying exactly the scopes the
// TaskSpec's Identity.Scope permitted. ttl overrides the broker default if >0.
// taskID associates the minted token with a task so RevokeAllForTask can
// enumerate it; pass the task id of the sandbox that will use this token.
func (b *Broker) Mint(caller, tenant, taskID string, scope []string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = b.defaultTTL
	}
	id, err := randID()
	if err != nil {
		return "", fmt.Errorf("identity: generate token id: %w", err)
	}
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

	// Track the live token so RevokeAllForTask can find it by task. This index
	// is best-effort state; failing to record it only weakens bulk revocation,
	// it never affects per-token Validate/Revoke paths.
	b.mu.Lock()
	if b.activeByTask[taskID] == nil {
		b.activeByTask[taskID] = make(map[string]struct{})
	}
	b.activeByTask[taskID][id] = struct{}{}
	b.mu.Unlock()

	if b.ledger != nil {
		if err := b.ledger.Append(audit.Record{
			Phase:    audit.PhaseGoalAuth,
			Subject:  caller,
			Action:   "mint",
			Params:   map[string]interface{}{"token_id": id, "tenant": tenant, "task": taskID, "scope": scope, "ttl": ttl.String()},
			Decision: audit.DecisionAllow,
			Reason:   "credential broker mint",
		}); err != nil {
			// Fail closed: a minted credential MUST have an audit trail. Roll
			// back the live index and refuse to hand out the token.
			b.mu.Lock()
			delete(b.activeByTask[taskID], id)
			b.mu.Unlock()
			return "", fmt.Errorf("identity: mint audit failed: %w", err)
		}
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
		// Lazily drop expired ids from the live index so the active set stays
		// bounded; this is purely bookkeeping hygiene.
		b.mu.Lock()
		for task, ids := range b.activeByTask {
			delete(ids, tok.ID)
			if len(ids) == 0 {
				delete(b.activeByTask, task)
			}
		}
		b.mu.Unlock()
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
		if err := b.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  tokenID,
			Action:   "revoke",
			Decision: audit.DecisionRevoke,
			Reason:   "credential broker revoke",
		}); err != nil {
			log.Printf("identity: failed to audit token revoke %s: %v", tokenID, err)
		}
	}
}

// RevokeAllForTask revokes every token minted for taskID in one shot. This is
// the bulk-revoke path the incident controller uses to "切断所有权限"
// (plan.md §11). It walks the in-memory live-token index populated at Mint
// time and moves each id into the revocation set; Validate() will then reject
// all of them with ErrRevoked. Returns the number of tokens revoked.
func (b *Broker) RevokeAllForTask(taskID string) int {
	b.mu.Lock()
	ids := make([]string, 0, len(b.activeByTask[taskID]))
	for id := range b.activeByTask[taskID] {
		ids = append(ids, id)
		b.revoked[id] = struct{}{}
	}
	// Drop the task's live set; remaining ids are now only in `revoked`.
	delete(b.activeByTask, taskID)
	b.mu.Unlock()

	if b.ledger != nil {
		if err := b.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  taskID,
			Action:   "revoke_all",
			Params:   map[string]interface{}{"revoked": len(ids)},
			Decision: audit.DecisionRevoke,
			Reason:   "bulk revoke for task",
		}); err != nil {
			log.Printf("identity: failed to audit bulk revoke for task %s: %v", taskID, err)
		}
	}
	return len(ids)
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
// ordering. The randomness comes from crypto/rand so the id is unpredictable.
func randID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), base64.RawURLEncoding.EncodeToString(b[:])), nil
}
