// Package pool implements the Warm Pool + Quota controls (plan.md §12).
//
// Rule: shared read-only images & caches, but NEVER shared task identity,
// workspace, or writable state. A warm pool pre-creates unattached sandboxes
// (SandboxTemplate) so a Task Claim can grab a READY one without paying the
// cold-start cost; quota limits how many any tenant may hold.
package pool

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"uml-container/internal/audit"
)

// SandboxState is the lifecycle of a pooled sandbox (not to be confused with
// task FSM state; this is pool-internal).
type SandboxState string

const (
	SandboxReady     SandboxState = "ready"     // pre-created, unattached
	SandboxClaimed   SandboxState = "claimed"   // attached to a task
	SandboxWarming   SandboxState = "warming"   // being created
	SandboxDestroying SandboxState = "destroying"
)

// Template is the blueprint for a warm sandbox (plan.md §12.2 SandboxTemplate).
type Template struct {
	Name      string
	BaseImage string
	Kernel    string
	Memory    string
	CPU       int
}

// Sandbox is one pooled instance.
type Sandbox struct {
	ID        string
	Template  string
	State     SandboxState
	TaskID    string    // when Claimed
	Tenant    string    // tenant that claimed it (for accurate Release accounting)
	CPU       int       // cpu reserved at claim (for accurate Release accounting)
	MemMB     int       // memory reserved at claim (for accurate Release accounting)
	CreatedAt time.Time
	ClaimedAt time.Time
}

// Quota is a tenant's resource ceiling (plan.md §12.3).
type Quota struct {
	MaxConcurrent int
	MaxCPU        int
	MaxMemoryMB   int
	MaxTasksPerHour int
}

// DefaultQuota is a sane starter quota.
func DefaultQuota() Quota {
	return Quota{
		MaxConcurrent:   4,
		MaxCPU:          4,
		MaxMemoryMB:     4096,
		MaxTasksPerHour: 20,
	}
}

// Errors
var (
	ErrQuotaExceeded = errors.New("pool: tenant quota exceeded")
	ErrNoCapacity    = errors.New("pool: no warm sandbox available and pool at capacity")
)

// Manager owns the warm pool and per-tenant quota counters.
type Manager struct {
	mu       sync.Mutex
	pool     []*Sandbox
	capacity int
	quotas   map[string]Quota
	// live counters per tenant
	running map[string]int     // tenant -> concurrent count
	cpu     map[string]int     // tenant -> cpu sum
	memMB   map[string]int     // tenant -> mem sum
	hourly  map[string][]time.Time // tenant -> task start times (last hour)

	// Factory creates a new warm sandbox. Controller wires this to the real
	// UML+vhost+overlay provisioning path.
	Factory func(tmpl Template) (string, error)
	// Destroyer tears down a sandbox.
	Destroyer func(id string) error

	ledger *audit.Ledger
}

// NewManager constructs a pool with a max capacity and quota table.
func NewManager(capacity int, ledger *audit.Ledger) *Manager {
	return &Manager{
		pool:     make([]*Sandbox, 0, capacity),
		capacity: capacity,
		quotas:   make(map[string]Quota),
		running:  make(map[string]int),
		cpu:      make(map[string]int),
		memMB:    make(map[string]int),
		hourly:   make(map[string][]time.Time),
		ledger:   ledger,
	}
}

// SetQuota installs a per-tenant quota.
func (m *Manager) SetQuota(tenant string, q Quota) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quotas[tenant] = q
}

// Warm pre-creates N sandboxes from a template so claims don't pay cold start.
// Returns the count actually created (may be < n if at capacity). The Factory
// call happens WITHOUT the manager lock held so a slow provisioner can't stall
// other tenants' Claim/Release/Stats.
func (m *Manager) Warm(tmpl Template, n int) int {
	created := 0
	for i := 0; i < n; i++ {
		// Check capacity under the lock, then release it for the Factory call.
		m.mu.Lock()
		if len(m.pool) >= m.capacity {
			m.mu.Unlock()
			break
		}
		m.mu.Unlock()

		var id string
		if m.Factory != nil {
			var err error
			id, err = m.Factory(tmpl)
			if err != nil {
				continue
			}
		} else {
			id = fmt.Sprintf("warm-%s-%d", tmpl.Name, time.Now().UnixNano())
		}

		m.mu.Lock()
		// Re-check capacity: another goroutine may have filled the pool.
		if len(m.pool) >= m.capacity {
			m.mu.Unlock()
			if m.Destroyer != nil {
				_ = m.Destroyer(id) // don't leak a sandbox we can't keep
			}
			break
		}
		m.pool = append(m.pool, &Sandbox{
			ID:        id,
			Template:  tmpl.Name,
			State:     SandboxReady,
			CreatedAt: time.Now(),
		})
		m.mu.Unlock()
		created++
	}
	return created
}

// Claim hands a READY sandbox to a task, subject to tenant quota. Returns the
// sandbox id or an error explaining the denial.
func (m *Manager) Claim(tenant string, tmpl Template, taskID string) (string, error) {
	// ---- phase 1: quota check under lock ----
	m.mu.Lock()
	q, ok := m.quotas[tenant]
	if !ok {
		q = DefaultQuota()
		m.quotas[tenant] = q
	}

	// prune hourly window
	now := time.Now()
	cutoff := now.Add(-time.Hour)
	var recent []time.Time
	for _, t := range m.hourly[tenant] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	m.hourly[tenant] = recent

	if len(recent) >= q.MaxTasksPerHour {
		m.deny(tenant, "hourly task rate")
		m.mu.Unlock()
		return "", fmt.Errorf("%w: hourly task rate for tenant %s", ErrQuotaExceeded, tenant)
	}
	if m.running[tenant] >= q.MaxConcurrent {
		m.deny(tenant, "concurrency")
		m.mu.Unlock()
		return "", fmt.Errorf("%w: concurrency for tenant %s", ErrQuotaExceeded, tenant)
	}
	if m.cpu[tenant]+tmpl.CPU > q.MaxCPU {
		m.deny(tenant, "cpu")
		m.mu.Unlock()
		return "", fmt.Errorf("%w: cpu for tenant %s", ErrQuotaExceeded, tenant)
	}
	wantMB := parseMemMB(tmpl.Memory)
	if m.memMB[tenant]+wantMB > q.MaxMemoryMB {
		m.deny(tenant, "memory")
		m.mu.Unlock()
		return "", fmt.Errorf("%w: memory for tenant %s", ErrQuotaExceeded, tenant)
	}

	// find a ready sandbox of the right template
	var idx = -1
	for i, s := range m.pool {
		if s.State == SandboxReady && s.Template == tmpl.Name {
			idx = i
			break
		}
	}
	if idx >= 0 {
		// Happy path: claim the warm sandbox in place.
		sb := m.pool[idx]
		sb.State = SandboxClaimed
		sb.TaskID = taskID
		sb.Tenant = tenant
		sb.CPU = tmpl.CPU
		sb.MemMB = wantMB
		sb.ClaimedAt = now
		m.accountClaim(tenant, tmpl, now)
		m.allow(tenant, "claimed-warm")
		id := sb.ID
		m.mu.Unlock()
		return id, nil
	}

	// No warm sandbox. Decide whether on-demand creation is allowed while we
	// still hold the lock, then release the lock for the external Factory call.
	canCreate := len(m.pool) < m.capacity && m.Factory != nil
	m.mu.Unlock()

	if !canCreate {
		m.mu.Lock()
		m.deny(tenant, "no capacity")
		m.mu.Unlock()
		return "", ErrNoCapacity
	}

	// ---- phase 2: Factory call WITHOUT the lock ----
	id, err := m.Factory(tmpl)
	if err != nil {
		m.mu.Lock()
		m.deny(tenant, "factory failed: "+err.Error())
		m.mu.Unlock()
		return "", fmt.Errorf("%w: factory: %v", ErrNoCapacity, err)
	}

	// ---- phase 3: re-check quota under lock and commit ----
	m.mu.Lock()
	defer m.mu.Unlock()
	// Capacity may have changed while the lock was released.
	if len(m.pool) >= m.capacity {
		m.mu.Unlock()
		if m.Destroyer != nil {
			_ = m.Destroyer(id)
		}
		m.mu.Lock()
		m.deny(tenant, "no capacity after race")
		return "", ErrNoCapacity
	}
	// Re-check concurrency/cpu/mem in case another claim sneaked in.
	if m.running[tenant] >= q.MaxConcurrent || m.cpu[tenant]+tmpl.CPU > q.MaxCPU || m.memMB[tenant]+wantMB > q.MaxMemoryMB {
		m.deny(tenant, "quota changed after factory")
		return "", fmt.Errorf("%w: quota for tenant %s changed during claim", ErrQuotaExceeded, tenant)
	}
	sb := &Sandbox{ID: id, Template: tmpl.Name, State: SandboxClaimed, TaskID: taskID, Tenant: tenant, CPU: tmpl.CPU, MemMB: wantMB, CreatedAt: now, ClaimedAt: now}
	m.pool = append(m.pool, sb)
	m.accountClaim(tenant, tmpl, now)
	m.allow(tenant, "created-on-demand")
	return id, nil
}

// Release returns a sandbox to the pool (after task completion) or destroys it.
// plan.md §12 implies warm sandboxes are reused; a tainted sandbox should be
// destroyed rather than recycled.
func (m *Manager) Release(id string, recycle bool) error {
	m.mu.Lock()
	for i, s := range m.pool {
		if s.ID != id {
			continue
		}
		// Release quota counters for the tenant that actually claimed this
		// sandbox. We trust the Tenant/CPU/MemMB recorded at Claim time rather
				// than re-deriving tenant from TaskID (which is unreliable).
		m.releaseQuotaLocked(s)

		if recycle {
			s.State = SandboxReady
			s.TaskID = ""
			s.Tenant = ""
			s.CPU = 0
			s.MemMB = 0
			s.ClaimedAt = time.Time{}
			m.mu.Unlock()
			return nil
		}
		// Destroyer is an external call; do NOT keep m.mu held across it.
		// Snapshot the fields we need, drop the entry, then destroy.
		m.pool = append(m.pool[:i], m.pool[i+1:]...)
		destroyer := m.Destroyer
		m.mu.Unlock()
		if destroyer != nil {
			if err := destroyer(id); err != nil {
				if m.ledger != nil {
					_ = m.ledger.Append(audit.Record{
						Phase: audit.PhaseExec, Subject: id, Action: "pool:destroy",
						Decision: audit.DecisionDeny, Reason: "destroyer failed: " + err.Error(),
					})
				}
				return fmt.Errorf("pool: destroy sandbox %s: %w", id, err)
			}
		}
		return nil
	}
	m.mu.Unlock()
	return fmt.Errorf("pool: sandbox %s not found", id)
}

// releaseQuotaLocked decrements the per-tenant counters recorded at Claim
// time for s. Caller MUST hold m.mu.
func (m *Manager) releaseQuotaLocked(s *Sandbox) {
	tenant := s.Tenant
	if tenant == "" {
		return // sandbox was never claimed through a quota path
	}
	if m.running[tenant] > 0 {
		m.running[tenant]--
	}
	m.cpu[tenant] -= s.CPU
	if m.cpu[tenant] < 0 {
		m.cpu[tenant] = 0
	}
	m.memMB[tenant] -= s.MemMB
	if m.memMB[tenant] < 0 {
		m.memMB[tenant] = 0
	}
}

// Stats returns pool occupancy for observability.
func (m *Manager) Stats() (ready, claimed, total int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	total = len(m.pool)
	for _, s := range m.pool {
		switch s.State {
		case SandboxReady:
			ready++
		case SandboxClaimed:
			claimed++
		}
	}
	return
}

// accountClaim updates the per-tenant counters after a successful claim.
func (m *Manager) accountClaim(tenant string, tmpl Template, now time.Time) {
	m.running[tenant]++
	m.cpu[tenant] += tmpl.CPU
	m.memMB[tenant] += parseMemMB(tmpl.Memory)
	m.hourly[tenant] = append(m.hourly[tenant], now)
}

func (m *Manager) allow(tenant, how string) {
	if m.ledger == nil {
		return
	}
	_ = m.ledger.Append(audit.Record{
		Phase: audit.PhaseGoalAuth, Subject: tenant, Action: "pool:claim",
		Decision: audit.DecisionAllow, Reason: how,
	})
}
func (m *Manager) deny(tenant, why string) {
	if m.ledger == nil {
		return
	}
	_ = m.ledger.Append(audit.Record{
		Phase: audit.PhaseGoalAuth, Subject: tenant, Action: "pool:claim",
		Decision: audit.DecisionDeny, Reason: why,
	})
}

// parseMemMB parses "512M"/"2G" into MB.
func parseMemMB(s string) int {
	var v int64
	var unit string
	fmt.Sscanf(s, "%d%s", &v, &unit)
	switch unit {
	case "G", "g", "GB", "gb":
		return int(v * 1024)
	case "", "M", "m", "MB", "mb":
		return int(v)
	case "K", "k", "KB", "kb":
		return int(v / 1024)
	}
	return int(v)
}
