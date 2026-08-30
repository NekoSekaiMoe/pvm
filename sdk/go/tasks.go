package sdk

// tasks.go — task control plane: list/get (short ids), pause/resume,
// snapshots/clone/rollback, metrics, console tail.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// TaskInfo mirrors the /api/tasks row.
type TaskInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	PID    int    `json:"pid"`
}

// TaskMetrics mirrors GET /api/tasks/:id/metrics.
type TaskMetrics struct {
	NetTxBytes     int64  `json:"net_tx_bytes"`
	EgressDenied   int64  `json:"egress_denied"`
	BudgetNetLimit *int64 `json:"budget_net_limit"`
	Deadline       string `json:"deadline"`
	TTL            string `json:"ttl"`
}

// SnapshotInfo is one task snapshot row.
type SnapshotInfo struct {
	ID        string            `json:"id"`
	CreatedAt string            `json:"created_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ListTasks lists tasks.
func (c *Client) ListTasks(ctx context.Context) ([]TaskInfo, error) {
	var out []TaskInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/tasks", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTask fetches one task; idOrPrefix accepts unique id prefixes.
func (c *Client) GetTask(ctx context.Context, idOrPrefix string) (*TaskInfo, error) {
	var out TaskInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/tasks/"+url.PathEscape(idOrPrefix), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PauseTask freezes a Running task (cgroup freeze; state Suspended).
func (c *Client) PauseTask(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/tasks/"+url.PathEscape(id)+"/pause", nil, nil)
}

// ResumeTask thaws a Suspended task.
func (c *Client) ResumeTask(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/tasks/"+url.PathEscape(id)+"/resume", nil, nil)
}

// TransitionTask drives the FSM explicitly (e.g. running -> review).
func (c *Client) TransitionTask(ctx context.Context, id, to, reason string) error {
	body := map[string]string{"to": to, "reason": reason}
	return c.doJSON(ctx, http.MethodPost, "/api/tasks/"+url.PathEscape(id)+"/transition", body, nil)
}

// TaskSnapshots lists a task's snapshots.
func (c *Client) TaskSnapshots(ctx context.Context, id string) ([]SnapshotInfo, error) {
	var out []SnapshotInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/tasks/"+url.PathEscape(id)+"/snapshots", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateTaskSnapshot captures an event-level snapshot.
func (c *Client) CreateTaskSnapshot(ctx context.Context, id, eventID string) (*SnapshotInfo, error) {
	body := map[string]string{"event_id": eventID}
	var out SnapshotInfo
	if err := c.doJSON(ctx, http.MethodPost, "/api/tasks/"+url.PathEscape(id)+"/snapshots", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CloneTask forks a task from one of its snapshots (O(1) CoW overlay).
func (c *Client) CloneTask(ctx context.Context, id, snapshotID, newID string) error {
	body := map[string]string{"snapshot": snapshotID}
	if newID != "" {
		body["new_id"] = newID
	}
	return c.doJSON(ctx, http.MethodPost, "/api/tasks/"+url.PathEscape(id)+"/clone", body, nil)
}

// RollbackTask restores a task to a snapshot (spec-fingerprint guarded).
func (c *Client) RollbackTask(ctx context.Context, id, snapshotID string) error {
	body := map[string]string{"snapshot_id": snapshotID}
	return c.doJSON(ctx, http.MethodPost, "/api/tasks/"+url.PathEscape(id)+"/rollback", body, nil)
}

// GetTaskMetrics fetches the per-task metrics view.
func (c *Client) GetTaskMetrics(ctx context.Context, id string) (*TaskMetrics, error) {
	var out TaskMetrics
	if err := c.doJSON(ctx, http.MethodGet, "/api/tasks/"+url.PathEscape(id)+"/metrics", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TaskConsoleTail returns the recent console output (ring buffer tail).
func (c *Client) TaskConsoleTail(ctx context.Context, id string) (string, error) {
	var out struct {
		Tail string `json:"tail"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/tasks/"+url.PathEscape(id)+"/console", nil, &out); err != nil {
		return "", err
	}
	return out.Tail, nil
}

// --- template build pipeline ---

// TemplateBuildStatus is GET /api/templates/:id/build.
type TemplateBuildStatus struct {
	Phase   string `json:"phase"`
	Pct     int    `json:"pct"`
	LogTail string `json:"log_tail"`
	Error   string `json:"error,omitempty"`
}

// TemplateBuildStatus fetches progress for a template build.
func (c *Client) TemplateBuildStatus(ctx context.Context, id string) (*TemplateBuildStatus, error) {
	var out TemplateBuildStatus
	if err := c.doJSON(ctx, http.MethodGet, "/api/templates/"+url.PathEscape(id)+"/build", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RebuildTemplate re-runs the build pipeline for a PENDING/FAILED template.
func (c *Client) RebuildTemplate(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/templates/"+url.PathEscape(id)+"/rebuild", nil, nil)
}

// WaitForTemplateReady polls the build endpoint until done/failed. The
// timeout bounds the whole wait — not just the space between responses —
// by deriving a cancellable context that is threaded into every poll.
func (c *Client) WaitForTemplateReady(ctx context.Context, id string, timeout time.Duration) (*TemplateBuildStatus, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	deadline := time.Now().Add(timeout)
	for {
		st, err := c.TemplateBuildStatus(ctx, id)
		if err != nil {
			return nil, err
		}
		if st.Phase == "done" || st.Phase == "failed" {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, fmt.Errorf("sdk: template %s still %s after %s", id, st.Phase, timeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}
