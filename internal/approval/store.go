package approval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"uml-container/internal/audit"
	"uml-container/internal/fsjson"
)

// Ticket.Consumed is declared in manager.go's Ticket struct via the
// consumeTicket mixin pattern; the fields below extend the manager with
// persistence, webhook notification, the Edit operation and one-shot
// consumption used by the policy gateway closure.

const defaultStoreFile = "approvals.json"

// EnablePersistence mirrors every ticket mutation to path (atomic fsjson
// write). Existing state at path is loaded eagerly. Failures to persist are
// logged, never fatal: an approval flow must keep working when the disk is
// full, but the operator must see why state may be lost.
func (m *Manager) EnablePersistence(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.persistPath = path
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("approval: persist dir: %w", err)
	}
	dump := struct {
		Tickets []Ticket `json:"tickets"`
	}{}
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &dump); err != nil {
			// A corrupt store must not brick the plane: start empty, keep
			// the broken file aside for forensics, and log loudly.
			_ = os.Rename(path, path+".corrupt")
			log.Printf("approval: store %s corrupt (%v); moved aside, starting empty", path, err)
		} else {
			for i := range dump.Tickets {
				t := dump.Tickets[i]
				m.tickets[t.ID] = &t
			}
		}
	}
	if err := m.persistLocked(); err != nil {
		return fmt.Errorf("approval: initial persist: %w", err)
	}
	return nil
}

// persistLocked writes the ticket store durably. Callers decide how to
// surface failures: ClaimFor REFUSES a claim when this fails (an
// unpersisted consume could replay after restart), while edit/expire paths
// only log (they are advisory state transitions).
func (m *Manager) persistLocked() error {
	if m.persistPath == "" {
		return nil
	}
	out := struct {
		Tickets []Ticket `json:"tickets"`
	}{Tickets: make([]Ticket, 0, len(m.tickets))}
	for _, t := range m.tickets {
		out.Tickets = append(out.Tickets, *t)
	}
	if err := fsjson.Write(m.persistPath, out); err != nil {
		return fmt.Errorf("approval: persist to %s: %w", m.persistPath, err)
	}
	return nil
}

// EnableWebhook registers a best-effort HTTP JSON notification endpoint.
// Ticket create/decide/edit events are POSTed asynchronously; delivery
// failures are logged and dropped (the audit ledger remains the durable
// record).
func (m *Manager) EnableWebhook(url string) {
	if url == "" {
		return
	}
	m.webhookURL = url
}

func (m *Manager) notify(event string, t Ticket) {
	url := m.webhookURL
	if url == "" {
		return
	}
	go func() {
		body, _ := json.Marshal(map[string]interface{}{"event": event, "ticket": t})
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("approval: webhook %s failed: %v", url, err)
			return
		}
		resp.Body.Close()
	}()
}

// Edit implements the "Edit" approval operation (plan.md §10): a pending
// ticket's params may be amended by the human, which re-arms it as pending
// with a fresh audit trail entry. Decided/expired tickets are immutable.
func (m *Manager) Edit(id string, params map[string]interface{}, reason, by string) (*Ticket, error) {
	m.mu.Lock()
	t, ok := m.tickets[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	if t.State != StatePending {
		m.mu.Unlock()
		return nil, ErrAlreadyDecided
	}
	if params != nil {
		t.Params = params
	}
	if reason != "" {
		t.Rollback = reason // edit rationale recorded alongside rollback context
	}
	now := m.now()
	t.EditedBy = by
	t.EditedAt = &now
	cp := *t
	m.persistLocked()
	m.mu.Unlock()

	if m.ledger != nil {
		_ = m.ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  by,
			Action:   "approval:edit:" + t.Tool,
			Params:   cp.Params,
			Decision: audit.DecisionApprove,
			Reason:   "ticket edited: " + reason,
		})
	}
	m.notify("edit", cp)
	return &cp, nil
}

// ApprovedFor returns the id of an approved, unconsumed ticket matching
// (task, tool, params) WITHOUT consuming it — an existence probe for UIs
// and tests. The gateway's one-shot unlock must use ClaimFor, which finds,
// consumes and persists atomically.
func (m *Manager) ApprovedFor(taskID, tool string, params map[string]interface{}) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tickets {
		if t.TaskID == taskID && t.Tool == tool && t.State == StateApproved &&
			!t.Consumed && sameParams(t.Params, params) {
			return t.ID, true
		}
	}
	return "", false
}

// ClaimFor atomically finds AND consumes an approved, unconsumed ticket
// matching (task, tool, params). Find + consume + persist happen under one
// critical section, so two concurrent executions can never both unlock on
// the same ticket. When persistence is enabled and the consume cannot be
// written, the claim is REFUSED (ok=false) — an unpersisted consume could
// replay the ticket after a restart.
func (m *Manager) ClaimFor(taskID, tool string, params map[string]interface{}) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tickets {
		if t.TaskID == taskID && t.Tool == tool && t.State == StateApproved &&
			!t.Consumed && sameParams(t.Params, params) {
			t.Consumed = true
			if err := m.persistLocked(); err != nil {
				// Roll the in-memory consume back: the durable store stays the
				// authority and the caller must not execute on this ticket.
				t.Consumed = false
				log.Printf("approval: refusing claim on %s: %v", t.ID, err)
				return "", false
			}
			return t.ID, true
		}
	}
	return "", false
}

// MarkConsumed burns an approved ticket after its one execution attempt.
// The gateway path uses ClaimFor instead (atomic); this stays for API
// compatibility and manual burns, so the signature stays void. Like
// ClaimFor, the in-memory consume is rolled back when the durable write
// fails: the persisted file is what a restart replays, so a memory-only
// consume would make the ticket look burned in-process while remaining
// claimable after a restart — the same replay hazard ClaimFor refuses.
func (m *Manager) MarkConsumed(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var touched *Ticket
	var prev bool
	if t, ok := m.tickets[id]; ok && t.State == StateApproved {
		touched, prev = t, t.Consumed
		t.Consumed = true
	}
	if err := m.persistLocked(); err != nil {
		if touched != nil {
			touched.Consumed = prev // memory must mirror the file, not run ahead of it
		}
		log.Printf("approval: mark-consumed persist failed: %v", err)
	}
}

// ExpirePending flips tickets whose deadline passed to StateExpired and
// returns how many it expired. Callers can drive it from a ticker; Pending()
// also expires lazily.
func (m *Manager) ExpirePending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.tickets {
		if t.State == StatePending && m.now().After(t.Deadline) {
			t.State = StateExpired
			n++
		}
	}
	if n > 0 {
		if err := m.persistLocked(); err != nil {
			log.Printf("approval: expire persist failed: %v", err)
		}
	}
	return n
}
