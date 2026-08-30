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
		return fmt.Errorf("pool: read store: %w", err)
	}
	m.persistLocked()
	return nil
}

func (m *Manager) persistLocked() {
	if m.persistPath == "" {
		return
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
		log.Printf("pool: persist to %s failed: %v", m.persistPath, err)
	}
}
