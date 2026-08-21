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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// LedgerRoot is the host-side audit root, intentionally separate from the
// task state dir so a sandbox never gets a path to its own ledger. Override
// via $PVM_AUDIT_ROOT for non-root / containerized runs.
var LedgerRoot = resolveRoot("PVM_AUDIT_ROOT", "/var/lib/uml-container/audit")

// Phase is one of the four evidence phases (plan.md §14.2).
type Phase string

const (
	PhaseGoalAuth Phase = "goal_auth"    // WHO · SCOPE
	PhaseSpec     Phase = "spec_version" // SPEC · VERSION
	PhaseExec     Phase = "execution"    // TOOL · FILE · NET
	PhaseRelease  Phase = "release"      // APPROVAL · HASH
)

// Decision is the outcome a gateway/controller recorded.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionConstrain Decision = "constrain"
	DecisionApprove   Decision = "approve"
	DecisionDeny      Decision = "deny"
	DecisionBlock     Decision = "block"
	DecisionRevoke    Decision = "revoke"
)

// Record is one ledger row.
type Record struct {
	Seq      int64       `json:"seq"`
	At       time.Time   `json:"at"`
	Task     string      `json:"task"`
	Tenant   string      `json:"tenant,omitempty"`
	Phase    Phase       `json:"phase"`
	Subject  string      `json:"subject"`          // who/what acted
	Action   string      `json:"action"`           // tool name / net op / ...
	Params   interface{} `json:"params,omitempty"` // bound params (no secrets)
	Decision Decision    `json:"decision"`
	Reason   string      `json:"reason,omitempty"`
	PrevHash string      `json:"prev_hash"`
	ThisHash string      `json:"hash"`
}

// File names inside a task's audit directory.
const (
	ledgerFileName = "ledger.jsonl"
	headFileName   = "head"
)

// taskIDRegex guards directory construction: a task id containing '/' or
// ".." would escape LedgerRoot (defense in depth — API/state/cgroup layers
// validate too).
var taskIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// Ledger is an append-only, hash-chained journal for one task.
type Ledger struct {
	task     string
	path     string
	headPath string
	mu       sync.Mutex
	lastHash string
	seq      int64
	// readOffset is how many bytes of the ledger file the in-memory tail
	// (lastHash/seq) already covers. Append uses it to resume decoding from
	// this offset instead of re-scanning the whole file, making back-to-back
	// appends amortized O(record delta) instead of O(total ledger size).
	readOffset int64
}

// Open returns (creating if needed) the ledger for a task.
func Open(task string) (*Ledger, error) {
	if !taskIDRegex.MatchString(task) {
		return nil, fmt.Errorf("audit: invalid task id %q", task)
	}
	dir := filepath.Join(LedgerRoot, task)
	// 0700: the ledger is evidence; group/other have no business reading it.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	// MkdirAll does not tighten pre-existing directories; best-effort chmod.
	_ = os.Chmod(dir, 0700)
	l := &Ledger{
		task:     task,
		path:     filepath.Join(dir, ledgerFileName),
		headPath: filepath.Join(dir, headFileName),
	}
	// Best-effort tightening of pre-existing files created by older versions
	// with looser modes.
	_ = os.Chmod(l.path, 0600)
	_ = os.Chmod(l.headPath, 0600)
	if err := l.loadTail(); err != nil {
		return nil, err
	}
	return l, nil
}

// loadTail performs a FULL scan of the ledger to seed lastHash/seq and
// records the consumed byte offset so later refreshes can resume from there.
// Missing file is fine (fresh ledger).
func (l *Ledger) loadTail() error {
	l.lastHash, l.seq, l.readOffset = "", 0, 0
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for {
		// A FRESH struct per record: json.Decode does not zero fields the
		// incoming object omits, so a reused struct would let record N's
		// fields bleed into record N+1 (Verify would then recompute hashes
		// over stale values and report phantom tampering).
		rec := Record{}
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		l.lastHash = rec.ThisHash
		l.seq = rec.Seq
	}
	l.readOffset = dec.InputOffset()
	return nil
}

// refreshTailLocked re-reads the tail from disk so an Append issued after
// another process wrote to the ledger picks up the new lastHash/seq.
// Incremental: when the file only grew (size >= readOffset) decoding resumes
// at the previously consumed offset, costing O(new records); when the file
// shrank or was rewritten (size < readOffset — truncation/tamper) it falls
// back to a full rescan. Caller MUST hold l.mu (and, for a true cross-writer
// update, an flock on the file).
func (l *Ledger) refreshTailLocked() error {
	fi, err := os.Stat(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			l.lastHash, l.seq, l.readOffset = "", 0, 0
			return nil
		}
		return err
	}
	if fi.Size() < l.readOffset {
		// Truncated or replaced underneath us: rescan everything.
		return l.loadTail()
	}
	if fi.Size() == l.readOffset {
		return nil
	}
	f, err := os.Open(l.path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(l.readOffset, io.SeekStart); err != nil {
		return err
	}
	dec := json.NewDecoder(f)
	for {
		// A FRESH struct per record: json.Decode does not zero fields the
		// incoming object omits, so a reused struct would let record N's
		// fields bleed into record N+1 (Verify would then recompute hashes
		// over stale values and report phantom tampering).
		rec := Record{}
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		l.lastHash = rec.ThisHash
		l.seq = rec.Seq
	}
	l.readOffset += dec.InputOffset()
	return nil
}

// Append writes a record and advances the hash chain. It holds an in-process
// mutex AND an exclusive flock on the ledger file so that multiple processes
// appending to the same task's ledger serialize correctly: each Append reads
// the current tail under the lock, advances seq/lastHash, and writes. Without
// the flock, two processes could both read the same tail and emit records
// sharing PrevHash/Seq, breaking Verify under concurrency.
func (l *Ledger) Append(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Open the file first and acquire the cross-process lock BEFORE computing
	// seq/hash. The single lock-protected refresh below is the authoritative
	// seed for seq/lastHash. A prior version also refreshed + seq++ here
	// (pre-lock) and then again under the lock, which ran seq++ twice and made
	// the first record of an empty ledger seq=2 instead of seq=1.
	// 0600: evidence file, owner-only.
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Cross-process mutex: hold an exclusive lock for the duration of the
	// append so concurrent writers serialize on the OS, not just in-process.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("audit: lock ledger: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	// Re-read tail under the lock: a peer may have appended since Open. This
	// single refresh drives seq/lastHash; no second increment happens.
	if err := l.refreshTailLocked(); err != nil {
		return fmt.Errorf("audit: refresh tail under lock: %w", err)
	}
	l.seq++
	r.Seq = l.seq
	r.Task = l.task
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	r.PrevHash = l.lastHash
	r.ThisHash = hashRecord(r, l.lastHash)

	// Encode to memory first so the exact byte count is known: the in-memory
	// readOffset watermark must advance by precisely what was written, or the
	// next incremental refresh would re-parse (or skip) bytes.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&r); err != nil {
		l.seq-- // nothing was written; unwind so a retry reuses this seq
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		l.seq--
		return err
	}
	l.lastHash = r.ThisHash
	l.readOffset += int64(buf.Len())

	// Anti-truncation watermark: persist "<seq> <lastHash>" in a sibling file
	// while still holding the flock. Verify compares the replayed record count
	// against this high-water mark, so chopping records off the end of the
	// ledger (even with a valid sub-chain) is detected. Written AFTER the
	// record itself: a crash between the two leaves head lagging, which only
	// weakens detection, never false-positives.
	head := fmt.Sprintf("%d %s\n", r.Seq, r.ThisHash)
	hf, err := os.OpenFile(l.headPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("audit: write head watermark: %w", err)
	}
	_, werr := hf.WriteString(head)
	cerr := hf.Close()
	if werr != nil {
		return fmt.Errorf("audit: write head watermark: %w", werr)
	}
	if cerr != nil {
		return fmt.Errorf("audit: close head watermark: %w", cerr)
	}
	_ = os.Chmod(l.headPath, 0600)
	return nil
}

// hashRecord computes the chained hash. The digest covers EVERY field that
// participates in the audit semantics: prev_hash, Seq, At, Task, Tenant,
// Phase, Subject, Action, Params, Decision, Reason. Modifying any of them on
// disk therefore breaks Verify. Params is encoded via json.Marshal, which
// sorts keys for map values (struct/slice order is the caller's responsibility
// — we freeze those via the concrete Record type).
//
// Every field is length-prefixed so adjacent values cannot collide regardless
// of content: without framing, concatenating "%s|%s" lets an attacker move a
// '|' between fields and forge a different field split that still hashes the
// same. The frame is "<label>=<len>:<bytes>"; ThisHash is excluded by
// construction (the caller passes prev, and Verify recomputes from the stored
// fields, never reading ThisHash back into the digest).
func hashRecord(r Record, prev string) string {
	h := sha256.New()
	writeFramed := func(label string, b []byte) {
		fmt.Fprintf(h, "%s=%d:", label, len(b))
		h.Write(b)
	}
	writeStr := func(label, s string) { writeFramed(label, []byte(s)) }

	writeStr("prev", prev)
	writeStr("seq", strconv.FormatInt(r.Seq, 10))
	writeStr("at", r.At.UTC().Format(time.RFC3339Nano))
	writeStr("task", r.Task)
	writeStr("tenant", r.Tenant)
	writeStr("phase", string(r.Phase))
	writeStr("subject", r.Subject)
	writeStr("action", r.Action)
	// Params is interface{}; json.Marshal sorts map keys for stable encoding.
	// A marshal error yields nil, framed as an empty field so the chain still
	// verifies — the caller is responsible for only storing serializable params.
	paramsEnc, _ := json.Marshal(r.Params)
	writeFramed("params", paramsEnc)
	writeStr("decision", string(r.Decision))
	writeStr("reason", r.Reason)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify replays the whole ledger and checks the hash chain. Returns the count
// of verified records, or an error describing the first broken link. When the
// head watermark exists (written by every Append since its introduction) and
// fewer records survive than it recorded, the ledger was truncated — reported
// even though the surviving prefix chain-validates. A missing head file skips
// the check (compatibility with pre-watermark data).
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
	for {
		// A FRESH struct per record: json.Decode does not zero fields the
		// incoming object omits, so a reused struct would let record N's
		// fields bleed into record N+1 (Verify would then recompute hashes
		// over stale values and report phantom tampering).
		rec := Record{}
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
	if seq, _, ok := l.readHead(); ok && int64(count) < seq {
		return count, fmt.Errorf("audit: ledger truncated: head watermark records seq %d but only %d records verify", seq, count)
	}
	return count, nil
}

// readHead parses the head watermark file ("<seq> <hash>"). ok=false when the
// file is missing (legacy ledger) or unparseable (never block verification on
// our own auxiliary file being corrupt — the chain itself stays authoritative).
func (l *Ledger) readHead() (seq int64, hash string, ok bool) {
	data, err := os.ReadFile(l.headPath)
	if err != nil {
		return 0, "", false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, "", false
	}
	s, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || s < 0 {
		return 0, "", false
	}
	return s, fields[1], true
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
