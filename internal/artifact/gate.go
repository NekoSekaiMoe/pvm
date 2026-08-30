// Package artifact implements the Artifact Gate (plan.md §7).
//
// Rule: the producer (the agent) can supply evidence, but cannot be the sole
// judge. The gate re-verifies the agent's claimed success in an independent
// context, using only the artifact bundle (diff/build/trace/hash), before any
// release (merge/deploy/send) is allowed.
//
// Four-step verification (plan.md §7.3):
//  1. Read-only baseline replay   - reproducibility
//  2. Re-run tests + scan         - correctness + secret scan
//  3. Sensitive-diff check        - block secrets/PII leakage
//  4. Bind artifact hash          - fingerprint the release
//
// The gate is a FRAMEWORK: each step is a pluggable Verifier. Default verifiers
// implement hash-binding and a secret-pattern scanner; the replay/test verifiers
// are injected by the controller (they need a throwaway sandbox to run in).
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"uml-container/internal/audit"
)

// Bundle is the evidence package the agent submits alongside a success claim.
type Bundle struct {
	TaskID    string            `json:"task_id"`
	Diff      string            `json:"diff"`       // unified diff text
	BuildLog  string            `json:"build_log"`  // build/run output
	Trace     []string          `json:"trace"`      // tool-call trace summary
	Files     map[string][]byte `json:"files"`      // declared output files
	ClaimedOK bool              `json:"claimed_ok"` // agent's own claim
}

// Verdict is the gate's decision.
type Verdict struct {
	Passed  bool              `json:"passed"`
	Hash    string            `json:"hash"`    // sha256 of the canonical bundle
	Reasons []string          `json:"reasons"` // why it failed (empty on pass)
	Step    map[string]string `json:"step"`    // per-step status
}

// Verifier is one check in the four-step pipeline. Returns ok + a reason
// (reason is empty on success, populated on failure).
type Verifier interface {
	Name() string
	Verify(b *Bundle) (ok bool, reason string)
}

// Gate runs the verifier pipeline.
type Gate struct {
	verifiers []Verifier
	// advisory names verifiers whose failure is recorded but does not fail
	// the release (e.g. secret_scan when spec.artifacts.block_secrets=false).
	advisory map[string]bool
	ledger   *audit.Ledger
	mu       sync.Mutex
}

// NewGate assembles a gate with the default verifiers plus any extras.
func NewGate(ledger *audit.Ledger, extra ...Verifier) *Gate {
	g := &Gate{ledger: ledger, advisory: map[string]bool{}}
	// default pipeline order matches plan.md §7.3
	g.verifiers = append(g.verifiers,
		&HashVerifier{},       // step 4 (computed first so later steps can cite it)
		&SecretScanVerifier{}, // step 3
	)
	g.verifiers = append(g.verifiers, extra...) // steps 1 & 2 injected here
	return g
}

// AddVerifier appends pipeline steps (used by FromSpec).
func (g *Gate) AddVerifier(vs ...Verifier) {
	g.mu.Lock()
	g.verifiers = append(g.verifiers, vs...)
	g.mu.Unlock()
}

// SetAdvisory marks a verifier's failures as non-blocking.
func (g *Gate) SetAdvisory(name string) {
	g.mu.Lock()
	g.advisory[name] = true
	g.mu.Unlock()
}

// Verify runs every verifier; the bundle passes only if ALL pass. The verdict
// (with the bound hash) is recorded in the audit ledger regardless of outcome.
// Verifiers don't share state, so they run WITHOUT the gate lock; the advisory
// and verifier snapshots are taken under g.mu, and even the ledger write is
// bounded by the ledger's own lock.
func (g *Gate) Verify(b *Bundle) *Verdict {
	v := &Verdict{Step: map[string]string{}, Passed: true}
	v.Hash = hashBundle(b)

	g.mu.Lock()
	advisory := make(map[string]bool, len(g.advisory))
	for k, av := range g.advisory {
		advisory[k] = av
	}
	verifiers := make([]Verifier, len(g.verifiers))
	copy(verifiers, g.verifiers)
	g.mu.Unlock()
	for _, ver := range verifiers {
		ok, reason := ver.Verify(b)
		switch {
		case ok:
			v.Step[ver.Name()] = "pass"
		case advisory[ver.Name()]:
			v.Step[ver.Name()] = "advisory: " + reason
		default:
			v.Step[ver.Name()] = "fail: " + reason
			v.Passed = false
			v.Reasons = append(v.Reasons, ver.Name()+": "+reason)
		}
	}

	g.mu.Lock()
	ledger := g.ledger
	g.mu.Unlock()
	if ledger != nil {
		dec := audit.DecisionAllow
		if !v.Passed {
			dec = audit.DecisionDeny
		}
		if err := ledger.Append(audit.Record{
			Phase:    audit.PhaseRelease,
			Subject:  b.TaskID,
			Action:   "artifact_gate",
			Params:   map[string]interface{}{"hash": v.Hash, "claimed_ok": b.ClaimedOK, "files": fileNames(b.Files)},
			Decision: dec,
			Reason:   strings.Join(v.Reasons, "; "),
		}); err != nil {
			// A release decision without an audit trail is unsafe: surface the
			// failure by failing the verdict and recording the reason.
			v.Passed = false
			v.Reasons = append(v.Reasons, "audit_ledger: "+err.Error())
			v.Step["audit_ledger"] = "fail: " + err.Error()
		}
	}
	return v
}

func fileNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- default verifiers ---

// HashVerifier computes the canonical hash of the bundle. It always "passes"
// (it's the binding step, not a pass/fail check) but records the hash on the
// verdict via the gate. Implemented as a verifier so it participates in the
// pipeline uniformity.
type HashVerifier struct{}

func (HashVerifier) Name() string { return "bind_hash" }
func (HashVerifier) Verify(b *Bundle) (bool, string) {
	// Always pass; the hash is already on the verdict. This step exists so the
	// audit row records the hash even when other steps fail.
	return true, ""
}

// hashBundle returns the canonical sha256 of a bundle. The digest covers the
// ACTUAL CONTENT of every evidence field (Diff, BuildLog, each Trace element,
// each File), not just lengths, so replacing a diff with a same-length forgery
// is detected. Map iteration order is normalized by sorting file names.
func hashBundle(b *Bundle) string {
	h := sha256.New()
	// Per-field content hashes: each field contributes its own digest, so a
	// change in any one cascades into the bundle hash.
	fmt.Fprintf(h, "task=%s|claimed=%t", b.TaskID, b.ClaimedOK)

	writeFieldHash := func(label, content string) {
		fh := sha256.Sum256([]byte(content))
		fmt.Fprintf(h, "|%s=%s", label, hex.EncodeToString(fh[:]))
	}
	writeFieldHash("diff", b.Diff)
	writeFieldHash("build", b.BuildLog)
	for _, t := range b.Trace {
		writeFieldHash("trace", t)
	}

	names := make([]string, 0, len(b.Files))
	for n := range b.Files {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		fh := sha256.Sum256(b.Files[n])
		fmt.Fprintf(h, "|%s=%s", n, hex.EncodeToString(fh[:]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SecretScanVerifier fails the gate if the diff or any file matches known
// secret patterns (AWS keys, GitHub tokens, private keys, high-entropy secrets).
// This is step 3 in plan.md §7.3 ("检查敏感差异").
type SecretScanVerifier struct{}

func (SecretScanVerifier) Name() string { return "secret_scan" }

var secretPatterns = []*regexp.Regexp{
	// AWS access key id
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// AWS secret (40 chars base64-ish after explicit label)
	regexp.MustCompile(`(?i)aws_secret_access_key["'\s:=]+[A-Za-z0-9/+=]{40}`),
	// GitHub personal access token (classic + fine-grained)
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	// Generic private key header
	regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	// Slack token
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
	// Generic api_key=... assignment with sufficient length
	regexp.MustCompile(`(?i)(api_key|apikey|secret_key|access_token)["'\s:=]+[A-Za-z0-9_\-]{20,}`),
}

func (SecretScanVerifier) Verify(b *Bundle) (bool, string) {
	// Corpus must include Trace: tool-call summaries can carry secrets too
	// (e.g. a tool arg containing an API key echoed into the trace).
	corpus := b.Diff + "\n" + b.BuildLog
	for _, t := range b.Trace {
		corpus += "\n" + t
	}
	for _, p := range secretPatterns {
		if p.MatchString(corpus) {
			return false, "secret pattern matched: " + p.String()
		}
	}
	for name, content := range b.Files {
		// files are bytes; scan as string
		s := string(content)
		for _, p := range secretPatterns {
			if p.MatchString(s) {
				return false, "secret pattern in file " + name + ": " + p.String()
			}
		}
	}
	return true, ""
}

// sortStrings is a tiny dependency-free sort to keep the package lean.
func sortStrings(s []string) {
	// insertion sort: file-name slices are small
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ErrRejected is returned by a ReleaseService when the gate rejected the bundle.
var ErrRejected = errors.New("artifact: gate rejected bundle")

// ReleaseService is the plan.md §7.2 third identity: only accepts gate-passed
// bundles. The controller wires a real backend (git merge, deploy, send) here.
type ReleaseService struct {
	Gate *Gate
	// Release executes the real-world effect. Only invoked when the gate passes.
	Release func(b *Bundle, v *Verdict) error
}

// Submit is the only entry point: gate first, release only on pass.
func (r *ReleaseService) Submit(b *Bundle) error {
	v := r.Gate.Verify(b)
	if !v.Passed {
		return fmt.Errorf("%w: %s", ErrRejected, strings.Join(v.Reasons, "; "))
	}
	if r.Release != nil {
		return r.Release(b, v)
	}
	return nil
}
