// Package approval implements the human-in-the-loop gate (plan.md §10).
//
// Design rules from plan.md:
//   - "只卡住副作用边界": only side-effectful actions pause for approval.
//   - An approval ticket binds TARGET + PARAMS + EVIDENCE + WHY + ROLLBACK; it
//     is NOT a blank check. Approving one param set does not approve another.
//   - Operations: Allow once | Edit | Reject.
//   - Human Override: human may PAUSE or take over at any time.
//
// This package is the ticket store + lifecycle. It does not render UI; the API
// layer exposes pending tickets and accepts decisions.
package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"uml-container/internal/audit"
)

// ErrInvalidDeadline marks a caller-supplied Deadline outside the sane
// acceptance window (already expired, or farther than 1h out, measured on
// the manager's clock). The API layer maps it to 400 so clients see their
// own bad input instead of a server error.
var ErrInvalidDeadline = errors.New("approval: invalid deadline")

// State of a ticket.
type State string

const (
	StatePending  State = "pending"
	StateApproved State = "approved"
	StateRejected State = "rejected"
	StateExpired  State = "expired"
)

// Ticket is a bound approval request (plan.md §10.3). Every field except State
// is immutable once created; only the state machine advances.
type Ticket struct {
	ID        string                 `json:"id"`
	TaskID    string                 `json:"task_id"`
	Target    string                 `json:"target"`   // e.g. "payments-service / production"
	Tool      string                 `json:"tool"`     // which tool wants to act
	Params    map[string]interface{} `json:"params"`   // bound params (PR #, file, ...)
	Evidence  string                 `json:"evidence"` // 18 tests · diff 42 lines · scan passed
	Why       string                 `json:"why"`      // 修复重复入账 · 预计 3min
	Rollback  string                 `json:"rollback"` // revert commit + feature flag
	CreatedAt time.Time              `json:"created_at"`
	Deadline  time.Time              `json:"deadline"`
	State     State                  `json:"state"`
	DecidedBy string                 `json:"decided_by,omitempty"`
	DecidedAt time.Time              `json:"decided_at,omitempty"`
	// Consumed records that the single authorized execution attempt backed
	// by this ticket already ran (policy gateway "Allow once").
	Consumed bool       `json:"consumed,omitempty"`
	EditedBy string     `json:"edited_by,omitempty"`
	EditedAt *time.Time `json:"edited_at,omitempty"`
}

// Manager is the in-memory ticket store. (MVP: process-local. A real deployment
// would back this with a DB; the API is shaped for that.)
type Manager struct {
	mu      sync.Mutex
	tickets map[string]*Ticket
	ledger  *audit.Ledger
	now     func() time.Time

	persistPath string
	webhookURL  string
}

// NewManager constructs a ticket store.
func NewManager(ledger *audit.Ledger) *Manager {
	return &Manager{
		tickets: make(map[string]*Ticket),
		ledger:  ledger,
		now:     time.Now,
	}
}

// Create registers a new pending ticket. Returns ErrAlreadyPending if an
// identical (same task+tool+params) ticket is already pending — the agent
// should not spam duplicate tickets.
func (m *Manager) Create(t Ticket) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// The manager's clock is the only basis for validity: a caller-supplied
	// CreatedAt must never extend a ticket's life, so both the default
	// deadline and the explicit-deadline window are computed from a single
	// server-side now.
	now := m.now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.Deadline.IsZero() {
		t.Deadline = now.Add(5 * time.Minute) // default approval window
	} else {
		// An explicit deadline is caller-supplied input: keep it inside a
		// sane window evaluated against the MANAGER's clock, not the
		// equally caller-supplied CreatedAt — otherwise a backdated CreatedAt
		// launders an already-expired or arbitrarily distant deadline. An
		// already-expired ticket could launder a decision (auto-expire logic
		// fires immediately); an arbitrarily distant one would pin a pending
		// gate open forever.
		if t.Deadline.Before(now) {
			return "", fmt.Errorf("%w: deadline %s is before the current time %s", ErrInvalidDeadline, t.Deadline.Format(time.RFC3339), now.Format(time.RFC3339))
		}
		if t.Deadline.After(now.Add(time.Hour)) {
			return "", fmt.Errorf("%w: deadline %s is more than 1h after the current time %s", ErrInvalidDeadline, t.Deadline.Format(time.RFC3339), now.Format(time.RFC3339))
		}
	}
	t.State = StatePending

	// dedupe: same task+tool+params already pending?
	for _, existing := range m.tickets {
		if existing.TaskID == t.TaskID && existing.Tool == t.Tool &&
			existing.State == StatePending && sameParams(existing.Params, t.Params) {
			return "", ErrAlreadyPending
		}
	}

	id, err := randID()
	if err != nil {
		return "", fmt.Errorf("approval: %w", err)
	}
	t.ID = id
	m.tickets[id] = &t
	cp := t
	if perr := m.persistLocked(); perr != nil {
		return "", fmt.Errorf("approval: persist ticket: %w", perr)
	}
	m.notify("create", cp)

	if m.ledger != nil {
		if err := m.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  t.TaskID,
			Action:   "approval:create:" + t.Tool,
			Params:   t.Params,
			Decision: audit.DecisionApprove, // "approval requested" semantically
			Reason:   t.Why,
		}); err != nil {
			log.Printf("approval: audit create failed for task %s: %v", t.TaskID, err)
		}
	}
	return id, nil
}

// Decide records a human decision on a ticket.
func (m *Manager) Decide(id string, approved bool, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tickets[id]
	if !ok {
		return ErrNotFound
	}
	if t.State != StatePending {
		return ErrAlreadyDecided
	}
	if m.now().After(t.Deadline) {
		t.State = StateExpired
		return ErrExpired
	}
	if approved {
		t.State = StateApproved
	} else {
		t.State = StateRejected
	}
	t.DecidedBy = by
	t.DecidedAt = m.now()
	cp := *t
	if perr := m.persistLocked(); perr != nil {
		return fmt.Errorf("approval: persist decision: %w", perr)
	}
	m.notify("decide", cp)

	if m.ledger != nil {
		dec := audit.DecisionApprove
		if !approved {
			dec = audit.DecisionDeny
		}
		if err := m.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  by,
			Action:   "approval:decide:" + t.Tool,
			Params:   map[string]interface{}{"ticket": id, "target": t.Target},
			Decision: dec,
			Reason:   t.Why,
		}); err != nil {
			log.Printf("approval: audit decide failed for ticket %s: %v", id, err)
		}
	}
	return nil
}

// Get returns a ticket by id.
func (m *Manager) Get(id string) (*Ticket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tickets[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

// Pending returns all pending tickets, optionally filtered by task.
func (m *Manager) Pending(taskID string) []Ticket {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Non-nil even when empty: /api/approvals serializes this directly and
	// JSON clients expect [], not null.
	out := make([]Ticket, 0, len(m.tickets))
	for _, t := range m.tickets {
		if t.State != StatePending {
			continue
		}
		if taskID != "" && t.TaskID != taskID {
			continue
		}
		// expire lazy
		if m.now().After(t.Deadline) {
			t.State = StateExpired
			continue
		}
		out = append(out, *t)
	}
	return out
}

// IsApproved reports whether a previously-created ticket was approved. Used by
// the policy gateway to decide whether to proceed on an ActionApprove tool.
func (m *Manager) IsApproved(taskID, tool string, params map[string]interface{}) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tickets {
		if t.TaskID == taskID && t.Tool == tool && t.State == StateApproved &&
			sameParams(t.Params, params) {
			return true
		}
	}
	return false
}

// Errors
var (
	ErrNotFound       = errors.New("approval: ticket not found")
	ErrAlreadyDecided = errors.New("approval: ticket already decided")
	ErrAlreadyPending = errors.New("approval: identical ticket already pending")
	ErrExpired        = errors.New("approval: ticket expired")
)

// sameParams reports whether two param maps are logically equal. It compares
// via canonical JSON encoding rather than ==, because Params is decoded from
// untrusted JSON and may contain nested maps/slices — comparing those with ==
// panics at runtime ("comparing uncomparable type map[string]interface{}").
// encoding/json sorts map keys, so the same logical value encodes identically.
func sameParams(a, b map[string]interface{}) bool {
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(aj) == string(bj)
}

// randID is a timestamp-prefixed 8-byte url-safe id. It FAILS CLOSED: a
// timestamp-only fallback id would be predictable (an attacker who can guess
// the creation second could address the ticket), and a system whose CSPRNG
// is unavailable has no business issuing approval credentials at all.
func randID() (string, error) {
	rs, err := randomString(8)
	if err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + rs, nil
}
