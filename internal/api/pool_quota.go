package api

// pool_quota.go — adapts the warm pool onto the lifecycle quota seam.
//
// The pool tracks each tenant's memory reservation; the lifecycle knows when a
// task is actually paused. Wiring them lets AutoPause free a tenant's memory
// quota (the host has reclaimed the pages) and lets AutoResume re-reserve it,
// while keeping the two packages independent.

// poolQuotaHooks bridges lifecycle.QuotaHooks onto the CURRENT pool manager.
// It resolves currentPool() per call so a controller calling
// RegisterPoolManager after server start still gets its own pool, instead of
// the process-global default captured at wiring time.
type poolQuotaHooks struct{}

func (poolQuotaHooks) SuspendByTask(taskID string) (bool, error) {
	m := currentPool()
	if m == nil {
		return false, nil
	}
	return m.SuspendByTask(taskID)
}

func (poolQuotaHooks) ResumeByTask(taskID string) (bool, error) {
	m := currentPool()
	if m == nil {
		return false, nil
	}
	return m.ResumeByTask(taskID)
}
