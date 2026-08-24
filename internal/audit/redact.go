// redact.go — shared secret redaction (脱敏) for the audit ledger.
//
// The ledger is append-only and hash-chained: anything written is written
// forever. Secrets must therefore be scrubbed BEFORE hashRecord runs inside
// Append (a post-write scrub would break Verify). This file lifts the
// redaction logic that used to be private to internal/policy into the audit
// package so every one of the ledger-writing planes (policy, approval,
// egress, incident, artifact, api, ...) is protected with zero call-site
// changes: Ledger.Append applies the redactor itself.
package audit

import (
	"regexp"
	"strings"
	"sync/atomic"
)

// RedactedPlaceholder replaces masked secret material.
const RedactedPlaceholder = "[REDACTED]"

// secretKeyDenylist: a Params key whose lowercase name CONTAINS any of these
// substrings is dropped entirely (deny-by-default, same conservative posture
// as the policy gateway's Observation scrub: "keyboard" is collateral).
var secretKeyDenylist = []string{
	"token", "secret", "password", "passwd", "key", "credential", "cookie", "auth",
}

// secretRedactionPatterns masks high-signal credential shapes in prose and
// string values, so an executor/upstream that echoes a token into a Reason,
// Subject, Action or a benignly-named Params value still gets masked before
// the bytes reach disk. Each pattern pairs with its replacement template:
// patterns with a capture group preserve the prefix (e.g. "?token=") so the
// redacted text still reads as a redacted ASSIGNMENT, not a hole.
var secretRedactionPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// GitHub tokens (classic + fine-grained + OAuth + refresh).
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`), RedactedPlaceholder},
	// AWS access key id.
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), RedactedPlaceholder},
	// Slack tokens.
	{regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), RedactedPlaceholder},
	// HTTP Bearer credentials.
	{regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+]{20,}`), RedactedPlaceholder},
	// URL query credentials: ?token=... &sig=... &api_key=... — upstream
	// error text routinely echoes the full request URL, query included.
	{
		regexp.MustCompile(`(?i)([?&](?:token|sig|signature|api_key|apikey|access_token|secret|password|key|auth)=)[^\s&"'<>]+`),
		"${1}" + RedactedPlaceholder,
	},
	// Generic key=value assignments in prose: token=..., password=... .
	// The 4-char minimum keeps benign mentions ("key=id") from being
	// over-masked while still catching real values.
	{
		regexp.MustCompile(`(?i)\b((?:token|secret|password|passwd|api_key|apikey|access_token|credential|cookie)=)[^\s&"'<>]{4,}`),
		"${1}" + RedactedPlaceholder,
	},
}

// redactionEnabled is the runtime kill-switch toggled via
// PUT /api/audit/redaction-policy. It defaults to ON; disabling stores NEW
// records unredacted (operator escape hatch for debugging — legacy rows are
// still redacted on READ by the API layer).
var redactionEnabled atomic.Bool

func init() { redactionEnabled.Store(true) }

// SetRedactionEnabled toggles the default redactor at runtime.
func SetRedactionEnabled(v bool) { redactionEnabled.Store(v) }

// RedactionEnabled reports the current redaction posture.
func RedactionEnabled() bool { return redactionEnabled.Load() }

// RedactionPatternCount exposes the number of active prose patterns (for the
// redaction-policy API).
func RedactionPatternCount() int { return len(secretRedactionPatterns) }

// SecretKeyDenylist returns a copy of the key denylist (for the
// redaction-policy API).
func SecretKeyDenylist() []string { return append([]string(nil), secretKeyDenylist...) }

// Redactor scrubs a Record in place BEFORE it is hashed and persisted.
// Implementations must be idempotent (Append may be preceded by a
// call-site scrub, e.g. the policy gateway's Observation sanitizer).
type Redactor interface {
	RedactRecord(r *Record)
}

type defaultRedactor struct{}

// DefaultRedactor returns the shared redactor applied by Ledger.Append and by
// the read-side defense in /api/audit/:id. It honors RedactionEnabled().
func DefaultRedactor() Redactor { return defaultRedactor{} }

// RedactRecord masks Params (recursive key-denylist + pattern scrub) and the
// free-text fields Subject/Action/Reason. Seq/At/Task/Hashes are evidence
// metadata and are never touched.
func (defaultRedactor) RedactRecord(r *Record) {
	if !redactionEnabled.Load() {
		return
	}
	r.Params = ScrubValue(r.Params)
	r.Subject = RedactSecrets(r.Subject)
	r.Action = RedactSecrets(r.Action)
	r.Reason = RedactSecrets(r.Reason)
}

// ScrubValue recursively scrubs a Params value: maps have secret-named keys
// dropped (and their surviving values recursively scrubbed), slices are
// element-wise scrubbed, and strings pass through RedactSecrets so a
// credential pattern in a benignly-named value (e.g.
// {"url": "...?token=ghp_..."}) is still masked. map[string]string and
// []string are promoted to their interface{} equivalents — the JSON encoding
// is identical, so the hash semantics are unchanged.
func ScrubValue(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, vv := range x {
			if IsSafeSummaryKey(k) {
				out[k] = ScrubValue(vv)
			}
		}
		return out
	case map[string]string:
		out := make(map[string]interface{}, len(x))
		for k, vv := range x {
			if IsSafeSummaryKey(k) {
				out[k] = RedactSecrets(vv)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, vv := range x {
			out[i] = ScrubValue(vv)
		}
		return out
	case []string:
		out := make([]interface{}, len(x))
		for i, vv := range x {
			out[i] = RedactSecrets(vv)
		}
		return out
	case string:
		return RedactSecrets(x)
	}
	return v
}

// IsSafeSummaryKey returns true for keys that may legitimately appear in
// persisted Params. Anything containing a secret-like substring is dropped.
func IsSafeSummaryKey(k string) bool {
	low := strings.ToLower(k)
	for _, bad := range secretKeyDenylist {
		if strings.Contains(low, bad) {
			return false
		}
	}
	return true
}

// RedactSecrets masks credential-looking substrings in s with "[REDACTED]".
func RedactSecrets(s string) string {
	for _, p := range secretRedactionPatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}
