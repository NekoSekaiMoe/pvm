// Package audit is the tamper-evident audit ledger (plan.md §14).
//
// Key invariant: the ledger lives OUTSIDE the sandbox at
// /var/lib/uml-container/audit/<task>/ledger.jsonl and is append-only. The
// agent cannot reach it from inside the guest, so it cannot rewrite its own
// history — the "证据在 Sandbox 之外 · Agent 不可改写" rule.
//
// Each record carries: subject (who) · params (what) · decision (allow/deny/...)
// · hash (chained SHA-256 over the previous record). A broken chain on read is
// a tamper signal.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LedgerRoot is the host-side audit root, intentionally separate from the
// task state dir so a sandbox never gets a path to its own ledger. Override
// via $PVM_AUDIT_ROOT for non-root / containerized runs.
var LedgerRoot = resolveRoot("PVM_AUDIT_ROOT", "/var/lib/uml-container/audit")

// Phase is one of the four evidence phases (plan.md §14.2).
type Phase string

const (
	PhaseGoalAuth Phase = "goal_auth"     // WHO · SCOPE
	PhaseSpec     Phase = "spec_version"  // SPEC · VERSION
	PhaseExec     Phase = "execution"     // TOOL · FILE · NET
	PhaseRelease  Phase = "release"       // APPROVAL · HASH
)

// Decision is the outcome a gateway/controller recorded.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionConstrain Decision = "constrain"
	DecisionApprove   Decision = "approve"
	DecisionDeny      Decision = "deny"
	DecisionBlock     Decision = "block"
	DecisionRevoke   Decision = "revoke"
)

// Record is one ledger row.
type Record struct {
	Seq       int64       `json:"seq"`
	At        time.Time   `json:"at"`
	Task      string      `json:"task"`
	Tenant    string      `json:"tenant,omitempty"`
	Phase     Phase       `json:"phase"`
	Subject   string      `json:"subject"`          // who/what acted
	Action    string      `json:"action"`           // tool name / net op / ...
	Params    interface{} `json:"params,omitempty"` // bound params (no secrets)
	Decision  Decision    `json:"decision"`
	Reason    string      `json:"reason,omitempty"`
	PrevHash  string      `json:"prev_hash"`
	ThisHash  string      `json:"hash"`
}

// Ledger is an append-only, hash-chained journal for one task.
type Ledger struct {
	task     string
	path     string
	mu       sync.Mutex
	lastHash string
	seq      int64
}

// Open returns (creating if needed) the ledger for a task.
func Open(task string) (*Ledger, error) {
	if task == "" {
		return nil, errors.New("audit: empty task id")
	}
	dir := filepath.Join(LedgerRoot, task)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	l := &Ledger{task: task, path: filepath.Join(dir, "ledger.jsonl")}
	if err := l.loadTail(); err != nil {
		return nil, err
	}
	return l, nil
}

// loadTail reads the last line to seed lastHash/seq without loading the whole
// file. Missing file is fine (fresh ledger).
func (l *Ledger) loadTail() error {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var rec Record
	for {
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		l.lastHash = rec.ThisHash
		l.seq = rec.Seq
	}
	return nil
}

// Append writes a record and advances the hash chain. It is process-locked via
// fcntl-style O_APPEND + the mu mutex; cross-process safety relies on the OS
// guaranteeing append writes up to PIPE_BUF are atomic for local files.
func (l *Ledger) Append(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	r.Seq = l.seq
	r.Task = l.task
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	r.PrevHash = l.lastHash
	r.ThisHash = hashRecord(r, l.lastHash)

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&r); err != nil {
		return err
	}
	l.lastHash = r.ThisHash
	return nil
}

// hashRecord computes the chained hash: sha256(prev_hash || canonical-json).
// Params is encoded canonically (sorted keys) so structurally identical
// records hash identically regardless of map iteration order.
func hashRecord(r Record, prev string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte("|"))
	enc, _ := json.Marshal(r.Params)
	h.Write(enc)
	h.Write([]byte("|"))
	fmt.Fprintf(h, "%s|%s|%s|%s|%s", r.Phase, r.Subject, r.Action, r.Decision, r.Reason)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify replays the whole ledger and checks the hash chain. Returns the count
// of verified records, or an error describing the first broken link.
func (l *Ledger) Verify() (int, error) {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	prev := ""
	count := 0
	var rec Record
	for {
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return count, err
		}
		if rec.PrevHash != prev {
			return count, fmt.Errorf("audit: broken chain at seq %d: prev_hash mismatch", rec.Seq)
		}
		want := hashRecord(rec, prev)
		if rec.ThisHash != want {
			return count, fmt.Errorf("audit: broken chain at seq %d: record tampered", rec.Seq)
		}
		prev = rec.ThisHash
		count++
	}
	return count, nil
}

// ReadAll returns the whole ledger in order. Used for RECONSTRUCT (plan.md §14.3).
func (l *Ledger) ReadAll() ([]Record, error) {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Record
	dec := json.NewDecoder(f)
	for {
		var r Record
		if err := dec.Decode(&r); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// resolveRoot picks a root directory from the environment when available so
// non-root runs (CI, containers, tests) can target a writable path.
func resolveRoot(envKey, def string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return def
}
