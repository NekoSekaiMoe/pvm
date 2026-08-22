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
	"log"
	"math"
	"strconv"
	"sync"
	"time"

	"uml-container/internal/audit"
)

// SandboxState is the lifecycle of a pooled sandbox (not to be confused with
// task FSM state; this is pool-internal).
type SandboxState string

const (
	SandboxReady      SandboxState = "ready"   // pre-created, unattached
	SandboxClaimed    SandboxState = "claimed" // attached to a task
	SandboxWarming    SandboxState = "warming" // being created
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
	TaskID    string // when Claimed
	Tenant    string // tenant that claimed it (for accurate Release accounting)
	CPU       int    // cpu reserved at claim (for accurate Release accounting)
	MemMB     int    // memory reserved at claim (for accurate Release accounting)
	CreatedAt time.Time
	ClaimedAt time.Time
}

// Quota is a tenant's resource ceiling (plan.md §12.3).
type Quota struct {
	MaxConcurrent   int
	MaxCPU          int
	MaxMemoryMB     int
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
	running map[string]int         // tenant -> concurrent count
	cpu     map[string]int         // tenant -> cpu sum
	memMB   map[string]int         // tenant -> mem sum
	hourly  map[string][]time.Time // tenant -> task start times (last hour)
	// pendingCleanups records sandboxes whose teardown after a rejected
	// claim/warm FAILED and must be retried (see destroy). The old code
	// discarded those Destroyer errors and silently leaked the sandbox.
	// Guarded by m.mu.
	pendingCleanups map[string]string // sandbox ID -> cleanup reason

	// cleanupSweeping marks an in-flight RetryCleanups sweep so concurrent
	// sweeps serialize instead of running Destroyer twice on the same
	// sandbox. Guarded by m.mu.
	cleanupSweeping bool

	// now supplies the current time for hourly-window pruning and sandbox
	// timestamps. A func field (defaulting to time.Now via NewManager) so
	// tests can pin the clock across an hourly boundary.
	now func() time.Time

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
		pool:            make([]*Sandbox, 0, capacity),
		capacity:        capacity,
		quotas:          make(map[string]Quota),
		running:         make(map[string]int),
		cpu:             make(map[string]int),
		memMB:           make(map[string]int),
		hourly:          make(map[string][]time.Time),
		pendingCleanups: make(map[string]string),
		now:             time.Now,
		ledger:          ledger,
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
			id = fmt.Sprintf("warm-%s-%d", tmpl.Name, m.now().UnixNano())
		}

		m.mu.Lock()
		// Re-check capacity: another goroutine may have filled the pool.
		if len(m.pool) >= m.capacity {
			m.mu.Unlock()
			// Don't leak a sandbox we can't keep; a failed teardown is
			// queued for the retry sweep instead of being discarded.
			m.destroy(id, "warm capacity recheck")
			break
		}
		m.pool = append(m.pool, &Sandbox{
			ID:        id,
			Template:  tmpl.Name,
			State:     SandboxReady,
			CreatedAt: m.now(),
		})
		m.mu.Unlock()
		created++
	}
	return created
}

// decisionLog is one quota decision collected while holding m.mu. The ledger
// append happens AFTER the lock is released (see flushDecisions): audit IO in
// the claim critical section stalls every other tenant's Claim/Release.
type decisionLog struct {
	allow  bool
	tenant string
	note   string
}

// Claim hands a READY sandbox to a task, subject to tenant quota. Returns the
// sandbox id or an error explaining the denial.
func (m *Manager) Claim(tenant string, tmpl Template, taskID string) (string, error) {
	var logs []decisionLog
	id, err := m.claim(tenant, tmpl, taskID, &logs)
	// Ledger appends run OUTSIDE m.mu (and outside the Factory call window).
	m.flushDecisions(logs)
	return id, err
}

// flushDecisions appends collected decisions to the audit ledger. Best-effort:
// a failed append never fails the claim it describes — but it is never
// SILENT either: each failure is logged the same way the egress gateway's
// record() logs its append failures, so a broken ledger surfaces in logs
// instead of vanishing quota history.
func (m *Manager) flushDecisions(logs []decisionLog) {
	if m.ledger == nil {
		return
	}
	for _, d := range logs {
		dec := audit.DecisionDeny
		if d.allow {
			dec = audit.DecisionAllow
		}
		if err := m.ledger.Append(audit.Record{
			Phase: audit.PhaseGoalAuth, Subject: d.tenant, Action: "pool:claim",
			Decision: dec, Reason: d.note,
		}); err != nil {
			log.Printf("pool: audit append failed for tenant %s: %v", d.tenant, err)
		}
	}
}

// recordDecision appends a decision to the caller-local log buffer. It
// touches no shared Manager state and performs no IO, so it needs no lock —
// neither m.mu nor any other.
func recordDecision(out *[]decisionLog, tenant, why string, allow bool) {
	*out = append(*out, decisionLog{allow: allow, tenant: tenant, note: why})
}

func (m *Manager) claim(tenant string, tmpl Template, taskID string, logs *[]decisionLog) (string, error) {
	// ---- phase 1: quota check under lock ----
	m.mu.Lock()
	q, ok := m.quotas[tenant]
	if !ok {
		q = DefaultQuota()
		m.quotas[tenant] = q
	}

	// prune hourly window (phase 3 re-prunes with a fresh reading after
	// the Factory call — see pruneHourlyLocked)
	now := m.now()
	m.pruneHourlyLocked(tenant, now)

	wantMB, err := parseMemMB(tmpl.Memory)
	if err != nil {
		recordDecision(logs, tenant, "bad template memory: "+err.Error(), false)
		m.mu.Unlock()
		return "", fmt.Errorf("pool: %w", err)
	}

	if len(m.hourly[tenant]) >= q.MaxTasksPerHour {
		recordDecision(logs, tenant, "hourly task rate", false)
		m.mu.Unlock()
		return "", fmt.Errorf("%w: hourly task rate for tenant %s", ErrQuotaExceeded, tenant)
	}
	if m.running[tenant] >= q.MaxConcurrent {
		recordDecision(logs, tenant, "concurrency", false)
		m.mu.Unlock()
		return "", fmt.Errorf("%w: concurrency for tenant %s", ErrQuotaExceeded, tenant)
	}
	if m.cpu[tenant]+tmpl.CPU > q.MaxCPU {
		recordDecision(logs, tenant, "cpu", false)
		m.mu.Unlock()
		return "", fmt.Errorf("%w: cpu for tenant %s", ErrQuotaExceeded, tenant)
	}
	if memExceeded(q.MaxMemoryMB, m.memMB[tenant], wantMB) {
		recordDecision(logs, tenant, "memory", false)
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
		m.accountClaim(tenant, tmpl.CPU, wantMB, now)
		recordDecision(logs, tenant, "claimed-warm", true)
		id := sb.ID
		m.mu.Unlock()
		return id, nil
	}

	// No warm sandbox. Decide whether on-demand creation is allowed while we
	// still hold the lock, then release the lock for the external Factory call.
	canCreate := len(m.pool) < m.capacity && m.Factory != nil
	m.mu.Unlock()

	if !canCreate {
		recordDecision(logs, tenant, "no capacity", false)
		return "", ErrNoCapacity
	}

	// ---- phase 2: Factory call WITHOUT the lock ----
	id, err := m.Factory(tmpl)
	if err != nil {
		recordDecision(logs, tenant, "factory failed: "+err.Error(), false)
		return "", fmt.Errorf("%w: factory: %v", ErrNoCapacity, err)
	}

	// ---- phase 3: re-check quota under lock and commit ----
	m.mu.Lock()
	// Re-read the tenant's quota instead of reusing the phase-1 snapshot: a
	// SetQuota call may have tightened (or loosened) the limits while the
	// Factory ran without the lock, and the rechecks below must enforce the
	// LATEST limits. A missing entry (never happens via SetQuota, which only
	// installs) mirrors phase 1's default fallback.
	q, ok = m.quotas[tenant]
	if !ok {
		q = DefaultQuota()
	}
	// Capacity may have changed while the lock was released.
	if len(m.pool) >= m.capacity {
		m.mu.Unlock()
		m.destroy(id, "capacity race after factory")
		recordDecision(logs, tenant, "no capacity after race", false)
		return "", ErrNoCapacity
	}
	// Re-prune the hourly window with a FRESH clock reading before the
	// recheck, mirroring phase 1: the Factory may have taken long enough
	// to cross an hourly boundary, and counting already-expired timestamps
	// here would wrongly reject the claim.
	now = m.now()
	m.pruneHourlyLocked(tenant, now)
	// Re-check hourly rate/concurrency/cpu/mem in case another claim sneaked
	// in while the Factory ran. The hourly recheck mirrors phase 1: without it,
	// N concurrent claims could blow past MaxTasksPerHour together.
	if len(m.hourly[tenant]) >= q.MaxTasksPerHour {
		m.mu.Unlock()
		m.destroy(id, "hourly quota recheck after factory")
		recordDecision(logs, tenant, "hourly task rate after factory", false)
		return "", fmt.Errorf("%w: hourly task rate for tenant %s changed during claim", ErrQuotaExceeded, tenant)
	}
	if m.running[tenant] >= q.MaxConcurrent || m.cpu[tenant]+tmpl.CPU > q.MaxCPU ||
		memExceeded(q.MaxMemoryMB, m.memMB[tenant], wantMB) {
		m.mu.Unlock()
		m.destroy(id, "quota recheck after factory")
		recordDecision(logs, tenant, "quota changed after factory", false)
		return "", fmt.Errorf("%w: quota for tenant %s changed during claim", ErrQuotaExceeded, tenant)
	}
	sb := &Sandbox{ID: id, Template: tmpl.Name, State: SandboxClaimed, TaskID: taskID, Tenant: tenant, CPU: tmpl.CPU, MemMB: wantMB, CreatedAt: now, ClaimedAt: now}
	m.pool = append(m.pool, sb)
	m.accountClaim(tenant, tmpl.CPU, wantMB, now)
	recordDecision(logs, tenant, "created-on-demand", true)
	m.mu.Unlock()
	return id, nil
}

// destroy tears down a sandbox built for a claim/warm that was subsequently
// rejected. It runs SYNCHRONOUSLY on the caller's goroutine — Destroyer is
// an external call and can block the rejection path — so callers must NOT
// hold m.mu. A Destroyer failure is NOT discarded: the id and reason are
// recorded in pendingCleanups for RetryCleanups, so a flaky teardown
// surfaces in logs and gets retried instead of leaking the sandbox with no
// trace; the rejection returned to the caller is unaffected either way.
func (m *Manager) destroy(id, reason string) {
	if m.Destroyer == nil {
		return
	}
	if err := m.Destroyer(id); err != nil {
		m.mu.Lock()
		m.queueCleanupLocked(id, reason)
		m.mu.Unlock()
		log.Printf("pool: destroy sandbox %s failed (%s): %v; queued for retry", id, reason, err)
	}
}

// queueCleanupLocked records a sandbox whose teardown failed. Caller MUST
// hold m.mu.
func (m *Manager) queueCleanupLocked(id, reason string) {
	if m.pendingCleanups == nil {
		m.pendingCleanups = make(map[string]string)
	}
	m.pendingCleanups[id] = reason
}

// RetryCleanups re-attempts destruction of every sandbox queued by a failed
// post-rejection teardown. Sweeps are serialized: while one is running the
// cleanupSweeping flag makes concurrent calls return immediately, so two
// snapshots of the queue cannot run Destroyer on the same sandbox twice
// (ids are snapshotted under the lock, but Destroyer runs without it).
// Best-effort and race-free: successful retries are removed from the queue;
// persistent failures stay queued for the next sweep (wire a periodic
// ticker to this for a reaper). The Destroyer runs WITHOUT m.mu held.
func (m *Manager) RetryCleanups() {
	m.mu.Lock()
	if m.cleanupSweeping {
		m.mu.Unlock()
		return
	}
	m.cleanupSweeping = true
	ids := make([]string, 0, len(m.pendingCleanups))
	for id := range m.pendingCleanups {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	// Clear the flag on EVERY exit path once the sweep has processed.
	defer func() {
		m.mu.Lock()
		m.cleanupSweeping = false
		m.mu.Unlock()
	}()
	if m.Destroyer == nil {
		return
	}
	for _, id := range ids {
		if err := m.Destroyer(id); err != nil {
			continue // stays queued for the next sweep
		}
		m.mu.Lock()
		delete(m.pendingCleanups, id)
		m.mu.Unlock()
	}
}

// PendingCleanups reports how many sandbox teardowns are awaiting retry.
func (m *Manager) PendingCleanups() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pendingCleanups)
}

// pruneHourlyLocked drops task-start timestamps older than one hour from
// the tenant's window. BOTH quota-check stages run this against their own
// clock reading: an expired entry left in place counts against
// MaxTasksPerHour forever. Caller MUST hold m.mu.
func (m *Manager) pruneHourlyLocked(tenant string, now time.Time) {
	cutoff := now.Add(-time.Hour)
	var recent []time.Time
	for _, t := range m.hourly[tenant] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	m.hourly[tenant] = recent
}

// memExceeded is the overflow-safe memory quota boundary check, used by
// BOTH check stages (phase 1 and the post-Factory recheck). The naive
// used+want > limit addition wraps int when usage sits near math.MaxInt —
// a legal value per parseMemMB — turning an over-quota claim into a false
// ALLOW. The subtraction cannot wrap: both operands are non-negative, so
// limit-used stays within [-math.MaxInt, math.MaxInt].
func memExceeded(limit, used, want int) bool {
	return want > limit-used
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
// Caller MUST hold m.mu. memMB is pre-parsed by the caller so a bad template
// memory string was already rejected at the quota-check stage.
func (m *Manager) accountClaim(tenant string, cpu, memMB int, now time.Time) {
	m.running[tenant]++
	m.cpu[tenant] += cpu
	m.memMB[tenant] += memMB
	m.hourly[tenant] = append(m.hourly[tenant], now)
}

// parseMemMB parses "512M"/"2G" into MB. Strict: unlike the old Sscanf-based
// version (where "1.5G" silently parsed as 1 MB), a malformed value or an
// unsupported/missing unit is an ERROR, mirroring internal/config.ParseMemory.
func parseMemMB(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty memory")
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("invalid memory %q", s)
	}
	v, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid memory %q", s)
	}
	var mb int64
	switch s[i:] {
	case "K", "k", "KB", "kb":
		// Round UP to whole MB: a value below 1024 KB still consumes at least
		// 1 MB of quota headroom, and truncation would let 1023K claim as 0 MB.
		// Quotient+remainder instead of the old (v+1023) pre-add: on the
		// largest int64 K value the pre-add overflows and wraps negative,
		// silently under-charging (actually crediting) quota.
		kb := v
		mb = kb / 1024
		if kb%1024 != 0 {
			mb++
		}
	case "M", "m", "MB", "mb":
		mb = v
	case "G", "g", "GB", "gb":
		if v > math.MaxInt64/1024 {
			return 0, fmt.Errorf("memory value overflow: %q", s)
		}
		mb = v * 1024
	default:
		return 0, fmt.Errorf("unsupported or missing memory unit %q in %q", s[i:], s)
	}
	// math.MaxInt is MaxInt32 on 32-bit and MaxInt64 on 64-bit platforms;
	// converting a larger MB count with int(mb) there would silently wrap.
	if mb > int64(math.MaxInt) {
		return 0, fmt.Errorf("memory value %q (%d MB) exceeds platform maximum %d MB", s, mb, int64(math.MaxInt))
	}
	return int(mb), nil
}
