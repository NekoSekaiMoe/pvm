package audit

// signing.go upgrades the tamper-evidence story (bucket-2 "无签名"): every
// record is signed with an ed25519 key held outside the ledger file, so a
// host-side attacker who rewrites the whole chain (and recomputes hashes)
// still cannot produce valid signatures without the key file. Online
// verification (a background re-verify of every open ledger) surfaces drift
// as a metric + log line instead of waiting for an offline audit.
//
// Threat model: the key lives at <audit-root>/key_ed25519 (0600). Root on
// the host can steal it — that is the documented single-host boundary; the
// ledger still binds "who wrote what" against everyone with less than root.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"uml-container/internal/metrics"
)

const (
	signingKeyFile = "key_ed25519"
	signingPubFile = "key_ed25519.pub"
)

var metricChainVerify = metrics.Counter("pvm_audit_chain_verifies_total", "Online ledger verifications", "outcome")

// Signer signs record hashes with ed25519.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// LoadOrCreateSigner loads (or generates) the signing key pair under dir.
func LoadOrCreateSigner(dir string) (*Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit signing: %w", err)
	}
	keyPath := filepath.Join(dir, signingKeyFile)
	if s, err := loadSignerFile(keyPath); err == nil {
		return s, nil
	} else if os.IsNotExist(err) {
		// No key yet — create one below.
	} else if errors.Is(err, errMalformedSignerKey) {
		// The file exists but does not parse. Usually permanent corruption,
		// but during a concurrent first boot it can be the winner's
		// half-written PEM caught between the O_EXCL create and the finished
		// write. Fall through to the create path: O_EXCL fails with IsExist
		// and adoption retries with backoff, so a permanently corrupt key
		// still errors — only after the bounded retry budget.
	} else {
		return nil, fmt.Errorf("audit signing: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// O_CREATE|O_EXCL: two processes enabling signing for the same root on
	// first boot must not each generate a key and overwrite the other —
	// their ledgers would then carry signatures verifiable only by one of
	// the keys. The loser of the race reloads the winner's key instead.
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Lost the race: adopt the winner's key. Between the winner's
			// O_EXCL create and the completed write the file can read back
			// empty or half-written PEM, so adoption retries with backoff
			// instead of failing (or recursing just once).
			return adoptWinnerSigner(keyPath)
		}
		return nil, err
	}
	if _, err := kf.Write(pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv})); err != nil {
		kf.Close()
		_ = os.Remove(keyPath) // never leave a truncated key behind
		return nil, err
	}
	if err := kf.Close(); err != nil {
		_ = os.Remove(keyPath)
		return nil, err
	}
	// Public key is best-effort: it only fails with the private key if we
	// just created the latter, so O_EXCL is enough (a stale .pub from an
	// interrupted older write must not mask the fresh key).
	_ = os.WriteFile(filepath.Join(dir, signingPubFile),
		pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub}), 0o644)
	return &Signer{priv: priv, pub: pub}, nil
}

// errMalformedSignerKey marks "key file exists but does not parse" —
// either permanent corruption or a concurrent writer's half-written PEM.
var errMalformedSignerKey = errors.New("audit signing: malformed key")

// loadSignerFile reads and parses the signer key at keyPath, distinguishing
// not-exist (the caller may create the key) from malformed (half-written or
// corrupt — surfaced via errMalformedSignerKey, never silently replaced).
// Read errors are returned raw so os.IsNotExist keeps working at call sites.
func loadSignerFile(keyPath string) (*Signer, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	var priv ed25519.PrivateKey
	if block, _ := pem.Decode(raw); block != nil && block.Type == "ED25519 PRIVATE KEY" {
		priv = ed25519.PrivateKey(block.Bytes)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: %s", errMalformedSignerKey, keyPath)
	}
	return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// adoptWinnerSigner loads a key that a concurrent process is creating via
// O_EXCL. Right after losing the race the winner's file may read back as
// empty or half-written PEM, so adoption is a bounded retry (10 attempts
// spaced 50ms apart) rather than a single read; it gives up with the
// attempt count instead of looping forever.
func adoptWinnerSigner(keyPath string) (*Signer, error) {
	const attempts = 10
	const delay = 50 * time.Millisecond
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(delay)
		}
		s, err := loadSignerFile(keyPath)
		if err == nil {
			return s, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("audit signing: could not adopt %s after %d attempts: %w", keyPath, attempts, lastErr)
}

// Sign returns a base64 signature over hash.
func (s *Signer) Sign(hash string) string {
	if s == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, []byte(hash)))
}

// Verify checks a base64 signature over hash.
func (s *Signer) Verify(hash, sigB64 string) bool {
	if s == nil || sigB64 == "" {
		return sigB64 == "" // unsigned records stay valid when no signer is armed
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(s.pub, []byte(hash), sig)
}

// signerForRoot caches one signer per audit root (process-wide).
var (
	signerMu    sync.Mutex
	signerCache = map[string]*Signer{}
)

// SignerForRoot returns the signer for an audit root, creating it when
// PVM_AUDIT_SIGNING=1 (or a key already exists). nil when signing is off.
func SignerForRoot(root string) *Signer {
	signerMu.Lock()
	defer signerMu.Unlock()
	if s, ok := signerCache[root]; ok {
		return s
	}
	keyExists := false
	if _, err := os.Stat(filepath.Join(root, signingKeyFile)); err == nil {
		keyExists = true
	}
	if !keyExists && os.Getenv("PVM_AUDIT_SIGNING") != "1" {
		return nil
	}
	s, err := LoadOrCreateSigner(root)
	if err != nil {
		log.Printf("audit signing: disabled for root %s: %v", root, err)
		return nil
	}
	signerCache[root] = s
	return s
}

// VerifySigned checks the signature of one record against the signer for
// recordRoot (the ledger's directory root).
func VerifySigned(recordRoot string, hash, sig string) bool {
	return SignerForRoot(recordRoot).Verify(hash, sig)
}

// --- online monitor ---

// openLedgers tracks every Ledger this process opened so the monitor can
// re-verify them periodically. Keyed by ledger path so repeated Open calls
// for the same task replace (rather than accumulate) entries; Close removes
// the registration.
var (
	openLedgersMu sync.Mutex
	openLedgers   = map[string]*Ledger{}
)

func registerLedger(l *Ledger) {
	openLedgersMu.Lock()
	openLedgers[l.path] = l
	openLedgersMu.Unlock()
}

func unregisterLedger(l *Ledger) {
	openLedgersMu.Lock()
	if cur, ok := openLedgers[l.path]; ok && cur == l {
		delete(openLedgers, l.path)
	}
	openLedgersMu.Unlock()
}

// Close unregisters this ledger from the online verification monitor. The
// ledger file stays on disk; holders should call Close once the task is gone
// so periodic re-verification does not sweep dead ledgers forever.
func (l *Ledger) Close() { unregisterLedger(l) }

// StartOnlineVerify launches the periodic re-verification loop (idempotent).
// A failing ledger is logged and counted; it never panics the process — the
// operator response is quarantine, and the incident plane can subscribe to
// the metric.
func StartOnlineVerify(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	onlineOnce.Do(func() {
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for range t.C {
				openLedgersMu.Lock()
				ledgers := make([]*Ledger, 0, len(openLedgers))
				for _, l := range openLedgers {
					ledgers = append(ledgers, l)
				}
				openLedgersMu.Unlock()
				for _, l := range ledgers {
					if _, err := l.Verify(); err != nil {
						metricChainVerify.Inc("tampered")
						log.Printf("audit ONLINE VERIFY FAILED for %s: %v", l.task, err)
					} else {
						metricChainVerify.Inc("ok")
					}
				}
			}
		}()
	})
}

var onlineOnce sync.Once

// jsonMarshal is a tiny hook so tests can rely on stdlib behavior only.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
