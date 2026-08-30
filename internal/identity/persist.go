package identity

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"uml-container/internal/fsjson"
)

// persist.go makes the broker durable across restarts (bucket-2 "identity
// 易失" gap): the HMAC signing key lives in a 0600 file so tokens minted
// before a restart still validate, and the revocation set is mirrored to a
// JSON file so revoked tokens cannot be "un-revoked" by bouncing the daemon.
//
// Threat-model note: a host root that can read the key file can forge tokens
// — that is inherent to symmetric signing on a single host; the ledger and
// jail boundary are the mitigations. An asymmetric backend (Vault/KMS) is the
// upgrade path; see plan.md §5.

const (
	keyFilePerm = 0o600
	revFilePerm = 0o600
)

// LoadOrCreateKey returns the signing key at path, creating a fresh 32-byte
// key when the file does not exist yet. The file is created with 0600 and
// fails closed on any other error (a half-readable key file must never be
// silently replaced — that would invalidate every outstanding token).
func LoadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("identity: empty key path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("identity: key dir: %w", err)
	}
	if raw, err := os.ReadFile(path); err == nil && len(raw) >= 16 {
		return raw, nil
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("identity: read key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	// O_EXCL create: never clobber a key that appeared concurrently.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFilePerm)
	if err != nil {
		if os.IsExist(err) {
			// Lost the race: read the winner's key.
			raw, rerr := os.ReadFile(path)
			if rerr == nil && len(raw) >= 16 {
				return raw, nil
			}
		}
		return nil, fmt.Errorf("identity: create key: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, fmt.Errorf("identity: write key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("identity: close key: %w", err)
	}
	return key, nil
}

// revocationFile is the JSON shape persisted to disk.
type revocationFile struct {
	// Revoked holds individual token ids.
	Revoked []string `json:"revoked"`
	// Tasks holds task-wide revocations (every token seen for the task after
	// the revocation moment is denied; see ValidateTaskGate).
	Tasks []string `json:"tasks,omitempty"`
	// SavedAt is informational.
	SavedAt time.Time `json:"saved_at"`
}

// PersistRevocations loads the revocation file at path into the broker and
// mirrors every later revocation back to it. Existing in-memory state that is
// NOT in the file is merged in on load (union), so a restart can never
// narrow the revocation set.
func (b *Broker) PersistRevocations(path string) error {
	if path == "" {
		return fmt.Errorf("identity: empty revocation path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("identity: revocation dir: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revPath = path
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		var rf revocationFile
		if jerr := json.Unmarshal(raw, &rf); jerr != nil {
			// Same policy as approvals: quarantine corrupt file, start from
			// in-memory state, persist it back.
			_ = os.Rename(path, path+".corrupt")
		} else {
			for _, id := range rf.Revoked {
				b.revoked[id] = struct{}{}
			}
			for _, t := range rf.Tasks {
				b.revokedTasks[t] = struct{}{}
			}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("identity: read revocations: %w", err)
	}
	b.persistRevLocked()
	return nil
}

func (b *Broker) persistRevLocked() {
	if b.revPath == "" {
		return
	}
	rf := revocationFile{SavedAt: time.Now().UTC()}
	for id := range b.revoked {
		rf.Revoked = append(rf.Revoked, id)
	}
	for t := range b.revokedTasks {
		rf.Tasks = append(rf.Tasks, t)
	}
	if err := fsjson.Write(b.revPath, rf); err != nil {
		// A failed persist is logged by fsjson callers; keep going — losing
		// the mirror temporarily must not break the live revocation path.
		_ = err
	}
}

// Refresh rotates a still-valid token: a new token is minted with the same
// caller/tenant/scope (ttl semantics as Mint), the old token id is revoked,
// and the caller receives the replacement. This is the credential broker's
// answer to short TTLs: clients refresh proactively instead of holding
// long-lived material.
func (b *Broker) Refresh(tokStr string, ttl time.Duration) (string, error) {
	tok, err := b.Validate(tokStr)
	if err != nil {
		return "", fmt.Errorf("identity: refresh: %w", err)
	}
	// Locate the task linkage so the replacement keeps RevokeAllForTask
	// coverage.
	b.mu.RLock()
	taskID := b.taskByToken[tok.ID]
	b.mu.RUnlock()

	fresh, err := b.Mint(tok.Caller, tok.Tenant, taskID, tok.Scope, ttl)
	if err != nil {
		return "", err
	}
	b.Revoke(tok.ID)
	return fresh, nil
}
