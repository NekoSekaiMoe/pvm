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
	"errors"
	"sync"
	"time"

	"uml-container/internal/audit"
)

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
	ID       string            `json:"id"`
	TaskID   string            `json:"task_id"`
	Target   string            `json:"target"`    // e.g. "payments-service / production"
	Tool     string            `json:"tool"`      // which tool wants to act
	Params   map[string]interface{} `json:"params"`   // bound params (PR #, file, ...)
	Evidence string            `json:"evidence"`  // 18 tests · diff 42 lines · scan passed
	Why      string            `json:"why"`       // 修复重复入账 · 预计 3min
	Rollback string            `json:"rollback"`  // revert commit + feature flag
	CreatedAt time.Time        `json:"created_at"`
	Deadline  time.Time        `json:"deadline"`
	State     State            `json:"state"`
	DecidedBy string           `json:"decided_by,omitempty"`
	DecidedAt time.Time        `json:"decided_at,omitempty"`
}

// Manager is the in-memory ticket store. (MVP: process-local. A real deployment
// would back this with a DB; the API is shaped for that.)
type Manager struct {
	mu      sync.Mutex
	tickets map[string]*Ticket
	ledger  *audit.Ledger
	now     func() time.Time
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

	if t.CreatedAt.IsZero() {
		t.CreatedAt = m.now()
	}
	if t.Deadline.IsZero() {
		t.Deadline = t.CreatedAt.Add(5 * time.Minute) // default approval window
	}
	t.State = StatePending

	// dedupe: same task+tool+params already pending?
	for _, existing := range m.tickets {
		if existing.TaskID == t.TaskID && existing.Tool == t.Tool &&
			existing.State == StatePending && sameParams(existing.Params, t.Params) {
			return "", ErrAlreadyPending
		}
	}

	id := randID()
	t.ID = id
	m.tickets[id] = &t

	if m.ledger != nil {
		_ = m.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  t.TaskID,
			Action:   "approval:create:" + t.Tool,
			Params:   t.Params,
			Decision: audit.DecisionApprove, // "approval requested" semantically
			Reason:   t.Why,
		})
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

	if m.ledger != nil {
		dec := audit.DecisionApprove
		if !approved {
			dec = audit.DecisionDeny
		}
		_ = m.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  by,
			Action:   "approval:decide:" + t.Tool,
			Params:   map[string]interface{}{"ticket": id, "target": t.Target},
			Decision: dec,
			Reason:   t.Why,
		})
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
	var out []Ticket
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

// sameParams is a shallow equality over the param maps. Values must be
// comparable (strings/numbers/bools); nested maps compare by identity.
func sameParams(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || av != bv {
			return false
		}
	}
	return true
}

// randID is a 12-byte url-safe id.
func randID() string {
	return time.Now().UTC().Format("20060102T150405Z") + "-" + randomString(8)
}
