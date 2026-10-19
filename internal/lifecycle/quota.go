package lifecycle

// quota.go — the seam between AutoPause and the warm pool's tenant quota.
//
// A paused sandbox holds no live guest memory (its state lives on disk or in
// a frozen-but-pageable process), so keeping the tenant's full memory
// reservation pinned would starve the tenant of quota headroom while the host
// has already reclaimed the pages. The pool owns that accounting, so the
// lifecycle calls these hooks on pause/resume:
//
//   - SuspendByTask releases the task's memory reservation (no-op for a task
//     that never came from the pool).
//   - ResumeByTask re-reserves it; ErrQuotaExceeded aborts the resume BEFORE
//     the guest is thawed, leaving the task suspended and retryable.
//
// The interface lives here (rather than importing the pool) so lifecycle stays
// independent of the pool package; api wires an adapter at server start.

// QuotaHooks releases/re-reserves a paused task's memory reservation.
type QuotaHooks interface {
	SuspendByTask(taskID string) (bool, error)
	ResumeByTask(taskID string) (bool, error)
}

// SetQuotaHooks installs the quota seam. Safe to call once at wiring time.
func (m *Manager) SetQuotaHooks(h QuotaHooks) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quota = h
}

// releaseQuotaLocked is a best-effort SuspendByTask: a pause must not fail
// merely because quota bookkeeping did (the guest is already stopped).
func (m *Manager) releaseQuota(taskID string) {
	m.mu.Lock()
	h := m.quota
	m.mu.Unlock()
	if h == nil {
		return
	}
	_, _ = h.SuspendByTask(taskID)
}

// reserveQuota re-reserves the task's memory before a resume thaws it. A
// missing reservation (task not from the pool) is not an error; a quota
// refusal is returned so the resume aborts with the task still suspended.
func (m *Manager) reserveQuota(taskID string) error {
	m.mu.Lock()
	h := m.quota
	m.mu.Unlock()
	if h == nil {
		return nil
	}
	_, err := h.ResumeByTask(taskID)
	return err
}
