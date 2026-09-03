package api

// pool_runtime.go gives the API's warm pool a REAL factory (bucket-3 "Warm
// 生成假 id"): every warmed sandbox becomes a state-recorded container
// directory (status=ready) that Claim can hand to a task and the lifecycle
// plane can see. Booting an actual UML kernel still belongs to the
// controller process (`agentpvm run` registers its own booting factory via
// RegisterPoolManager); at the API layer "real" means durable, inspectable
// records — no more "warm-<ts>" phantoms.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"uml-container/internal/metrics"
	"uml-container/internal/pool"
	"uml-container/internal/state"
)

// Pool capacity gauges (host_sandbox view), refreshed at scrape time.
var (
	poolReadyGauge   = metrics.Gauge("pvm_pool_ready", "Warm-pool sandboxes ready to claim")
	poolClaimedGauge = metrics.Gauge("pvm_pool_claimed", "Warm-pool sandboxes claimed by tasks")
	poolTotalGauge   = metrics.Gauge("pvm_pool_total", "Total sandboxes tracked by the warm pool")
)

func initPoolRuntime() {
	m := currentPool()
	if root := state.RootDir; root != "" {
		if err := m.EnablePersistence(filepath.Join(root, "pool.json")); err != nil {
			log.Printf("pool: persistence disabled: %v", err)
		}
	}
	// Pool gauges refresh at scrape time (host_sandbox view).
	metrics.OnRender(func() {
		ready, claimed, total := m.Stats()
		poolReadyGauge.Set(float64(ready))
		poolClaimedGauge.Set(float64(claimed))
		poolTotalGauge.Set(float64(total))
	})
	if m.Factory == nil {
		m.Factory = stateRecordedFactory
	}
	if m.Destroyer == nil {
		m.Destroyer = stateRecordedDestroyer
	}
}

// stateRecordedFactory materializes a READY sandbox as a state record.
func stateRecordedFactory(t pool.Template) (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pool factory: %w", err)
	}
	id := "warm-" + time.Now().UTC().Format("20060102T150405Z") + "-" + base64.RawURLEncoding.EncodeToString(b[:])
	st := &state.ContainerState{
		ID:        id,
		Name:      "warm:" + t.Name,
		Status:    state.StatusReady,
		StartedAt: time.Now().UTC(),
	}
	if err := state.SaveState(id, st); err != nil {
		return "", fmt.Errorf("pool factory: save state: %w", err)
	}
	return id, nil
}

// stateRecordedDestroyer removes the warmed sandbox's state directory.
func stateRecordedDestroyer(id string) error {
	dir, err := state.ContainerDir(id)
	if err != nil {
		return nil // invalid ids were never materialized
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil // already gone: idempotent
	}
	return os.RemoveAll(dir)
}
