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
	if raw, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "ED25519 PRIVATE KEY" {
			return nil, fmt.Errorf("audit signing: malformed %s", signingKeyFile)
		}
		priv := ed25519.PrivateKey(block.Bytes)
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("audit signing: bad key size")
		}
		return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("audit signing: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, signingPubFile),
		pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub}), 0o644); err != nil {
		return nil, err
	}
	return &Signer{priv: priv, pub: pub}, nil
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
// re-verify them periodically.
var (
	openLedgersMu sync.Mutex
	openLedgers   = map[*Ledger]struct{}{}
)

func registerLedger(l *Ledger) {
	openLedgersMu.Lock()
	openLedgers[l] = struct{}{}
	openLedgersMu.Unlock()
}

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
				for l := range openLedgers {
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
