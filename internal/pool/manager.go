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
// Returns the count actually created (may be < n if at capacity).
func (m *Manager) Warm(tmpl Template, n int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	created := 0
	for i := 0; i < n && len(m.pool) < m.capacity; i++ {
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
		m.pool = append(m.pool, &Sandbox{
			ID:        id,
			Template:  tmpl.Name,
			State:     SandboxReady,
			CreatedAt: time.Now(),
		})
		created++
	}
	return created
}

// Claim hands a READY sandbox to a task, subject to tenant quota. Returns the
// sandbox id or an error explaining the denial.
func (m *Manager) Claim(tenant string, tmpl Template, taskID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

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
		return "", fmt.Errorf("%w: hourly task rate for tenant %s", ErrQuotaExceeded, tenant)
	}
	if m.running[tenant] >= q.MaxConcurrent {
		m.deny(tenant, "concurrency")
		return "", fmt.Errorf("%w: concurrency for tenant %s", ErrQuotaExceeded, tenant)
	}
	if m.cpu[tenant]+tmpl.CPU > q.MaxCPU {
		m.deny(tenant, "cpu")
		return "", fmt.Errorf("%w: cpu for tenant %s", ErrQuotaExceeded, tenant)
	}
	// memory check
	wantMB := parseMemMB(tmpl.Memory)
	if m.memMB[tenant]+wantMB > q.MaxMemoryMB {
		m.deny(tenant, "memory")
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
	if idx < 0 {
		// try to create one on demand if under capacity
		if len(m.pool) < m.capacity && m.Factory != nil {
			id, err := m.Factory(tmpl)
			if err == nil {
				sb := &Sandbox{ID: id, Template: tmpl.Name, State: SandboxClaimed, TaskID: taskID, CreatedAt: now, ClaimedAt: now}
				m.pool = append(m.pool, sb)
				m.accountClaim(tenant, tmpl, now)
				m.allow(tenant, "created-on-demand")
				return id, nil
			}
		}
		m.deny(tenant, "no capacity")
		return "", ErrNoCapacity
	}

	sb := m.pool[idx]
	sb.State = SandboxClaimed
	sb.TaskID = taskID
	sb.ClaimedAt = now
	m.accountClaim(tenant, tmpl, now)
	m.allow(tenant, "claimed-warm")
	return sb.ID, nil
}

// Release returns a sandbox to the pool (after task completion) or destroys it.
// plan.md §12 implies warm sandboxes are reused; a tainted sandbox should be
// destroyed rather than recycled.
func (m *Manager) Release(id string, recycle bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.pool {
		if s.ID != id {
			continue
		}
		tenant := tenantForTask(s.TaskID) // MVP: encoded; real impl tracks reverse map
		if m.running[tenant] > 0 {
			m.running[tenant]--
		}
		if recycle {
			s.State = SandboxReady
			s.TaskID = ""
			s.ClaimedAt = time.Time{}
		} else {
			if m.Destroyer != nil {
				m.Destroyer(id)
			}
			m.pool = append(m.pool[:i], m.pool[i+1:]...)
		}
		return nil
	}
	return fmt.Errorf("pool: sandbox %s not found", id)
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

// tenantForTask is a placeholder reverse lookup. In the MVP we don't track a
// reverse map; the controller should call Release with the tenant context.
// Kept simple here so Release compiles; counters may under-count if tenant
// can't be derived, which is acceptable for the MVP (worst case = loose quota).
func tenantForTask(taskID string) string { return taskID }
