package pool

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"uml-container/internal/fsjson"
)

// persist.go mirrors pool + quota state to disk (bucket-3 "pool 纯内存重启
// 清零"): a restarted server reloads warm sandboxes and tenant quotas instead
// of forgetting them. Live counters (running/cpu/memMB/hourly) are rebuilt
// lazily from claimed entries on load; hourly windows reset conservatively
// (an empty window can only under-count, never over-charge).

type poolFile struct {
	Pool     []Sandbox        `json:"pool"`
	Quotas   map[string]Quota `json:"quotas"`
	Capacity int              `json:"capacity"`
	SavedAt  time.Time        `json:"saved_at"`
}

// persistSnapshot captures the pre-restore manager state so a failed
// EnablePersistence can roll the restore back atomically: without it, a
// first-persist failure would leave restored pool entries and rebuilt quota
// counters in memory, and a later retry on the same path would append the
// same sandboxes twice and double the counters.
type persistSnapshot struct {
	poolLen  int
	quotas   map[string]Quota
	capacity int
	running  map[string]int
	cpu      map[string]int
	memMB    map[string]int
	hourly   map[string][]time.Time
}

func (m *Manager) snapshotLocked() persistSnapshot {
	q := make(map[string]Quota, len(m.quotas))
	for k, v := range m.quotas {
		q[k] = v
	}
	r := make(map[string]int, len(m.running))
	for k, v := range m.running {
		r[k] = v
	}
	cp := make(map[string]int, len(m.cpu))
	for k, v := range m.cpu {
		cp[k] = v
	}
	mm := make(map[string]int, len(m.memMB))
	for k, v := range m.memMB {
		mm[k] = v
	}
	h := make(map[string][]time.Time, len(m.hourly))
	for k, v := range m.hourly {
		h[k] = append([]time.Time(nil), v...)
	}
	return persistSnapshot{
		poolLen: len(m.pool), quotas: q, capacity: m.capacity,
		running: r, cpu: cp, memMB: mm, hourly: h,
	}
}

func (m *Manager) restoreLocked(s persistSnapshot) {
	m.pool = m.pool[:s.poolLen]
	m.quotas = s.quotas
	m.capacity = s.capacity
	m.running = s.running
	m.cpu = s.cpu
	m.memMB = s.memMB
	m.hourly = s.hourly
}

// EnablePersistence loads state from path and mirrors every mutation back.
func (m *Manager) EnablePersistence(path string) error {
	if path == "" {
		return fmt.Errorf("pool: empty persistence path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("pool: persist dir: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Idempotency guard: a second EnablePersistence would re-append the
	// same sandboxes and double the rebuilt quota counters, letting one
	// ready sandbox be claimed twice. One Manager, one store.
	if m.persistPath != "" {
		return fmt.Errorf("pool: persistence already enabled (%s); re-enabling would duplicate restored sandboxes", m.persistPath)
	}
	m.persistPath = path
	snap := m.snapshotLocked()
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		var pf poolFile
		if jerr := json.Unmarshal(raw, &pf); jerr != nil {
			_ = os.Rename(path, path+".corrupt")
			log.Printf("pool: store %s corrupt (%v); moved aside", path, jerr)
		} else {
			for i := range pf.Pool {
				s := pf.Pool[i]
				m.pool = append(m.pool, &s)
			}
			for k, v := range pf.Quotas {
				m.quotas[k] = v
			}
			if pf.Capacity > 0 {
				m.capacity = pf.Capacity
			}
			// Rebuild live counters from claimed entries so quota checks stay
			// correct after a restart.
			for _, s := range m.pool {
				if s.State == SandboxClaimed && s.Tenant != "" {
					m.running[s.Tenant]++
					m.cpu[s.Tenant] += s.CPU
					m.memMB[s.Tenant] += s.MemMB
					m.hourly[s.Tenant] = append(m.hourly[s.Tenant], s.ClaimedAt)
				}
			}
		}
	} else if err != nil && !os.IsNotExist(err) {
		// Clear persistPath before failing: leaving it set would poison the
		// idempotency guard (a later EnablePersistence with a VALID path is
		// rejected) and keep every mutation writing to the unreadable path.
		m.persistPath = ""
		return fmt.Errorf("pool: read store: %w", err)
	}
	if err := m.persistLocked(); err != nil {
		// Fall back to pure in-memory mode, matching the comment above: the
		// caller asked for durable state and the very first snapshot could
		// not be written — keeping persistPath set would make every later
		// mutation fail the same way while still pretending to be durable.
		// The restore is rolled back too, so a retry after the storage issue
		// is fixed cannot duplicate the restored sandboxes or quota counters.
		m.restoreLocked(snap)
		m.persistPath = ""
		return fmt.Errorf("pool: initial persist: %w", err)
	}
	return nil
}

// persistLocked mirrors the manager state to the store file. Errors are
// returned, not logged: mutation callers decide whether a failed mirror is
// fatal (EnablePersistence refuses durability and falls back to memory) or
// just observable (logged and the in-memory mutation stands).
func (m *Manager) persistLocked() error {
	if m.persistPath == "" {
		return nil
	}
	pf := poolFile{
		Pool:     make([]Sandbox, 0, len(m.pool)),
		Quotas:   m.quotas,
		Capacity: m.capacity,
		SavedAt:  time.Now().UTC(),
	}
	for _, s := range m.pool {
		if s != nil {
			pf.Pool = append(pf.Pool, *s)
		}
	}
	if err := fsjson.Write(m.persistPath, pf); err != nil {
		return fmt.Errorf("persist to %s: %w", m.persistPath, err)
	}
	return nil
}
