package sdk

// planes.go — the governance control planes: tool gateway exec, approvals,
// identity broker, incidents, pool.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// --- /api/exec (tool gateway) ---

// ErrApprovalRequired is returned when the gateway parked the request behind
// an approval ticket (HTTP 202); TicketID names it.
var ErrApprovalRequired = errors.New("sdk: approval required")

// ExecResult is the gateway's structured observation.
type ExecResult struct {
	OK      bool                   `json:"ok"`
	Summary string                 `json:"summary"`
	Result  map[string]interface{} `json:"result,omitempty"`
	Reason  string                 `json:"reason,omitempty"`
}

// execAccepted is the 202 body.
type execAccepted struct {
	Status      string `json:"status"`
	Ticket      string `json:"ticket"`
	TicketError string `json:"ticket_error"`
}

// Exec submits a tool call ("name key=value ...") through the task's policy
// gateway. A denied call returns the wrapped error; an approval-parked call
// returns ErrApprovalRequired with the ticket id (decide it, then Exec again
// — one approval unlocks exactly one attempt).
func (c *Client) Exec(ctx context.Context, task, command string) (*ExecResult, error) {
	// Custom transport step: 202 is a success-shaped answer we surface as a
	// sentinel error, so drive the request by hand.
	var raw []byte
	if body, err := marshalJSON(map[string]string{"cmd": command}); err != nil {
		return nil, err
	} else {
		raw = body
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.APIURL+"/api/exec?task="+url.QueryEscape(task), readerOrNil(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		var acc execAccepted
		if err := decodeInto(resp, &acc); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: ticket=%s (decide via DecideApproval, then Exec again)", ErrApprovalRequired, acc.Ticket)
	}
	var out ExecResult
	if err := decodeInto(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- /api/approvals ---

// ApprovalTicket mirrors the ticket record.
type ApprovalTicket struct {
	ID       string                 `json:"id"`
	TaskID   string                 `json:"task_id"`
	Tool     string                 `json:"tool"`
	Params   map[string]interface{} `json:"params"`
	Target   string                 `json:"target"`
	Why      string                 `json:"why"`
	Rollback string                 `json:"rollback"`
	State    string                 `json:"state"`
	Consumed bool                   `json:"consumed,omitempty"`
}

// ListApprovals lists pending tickets (optionally filtered by task).
func (c *Client) ListApprovals(ctx context.Context, task string) ([]ApprovalTicket, error) {
	path := "/api/approvals"
	if task != "" {
		path += "?task=" + url.QueryEscape(task)
	}
	var out []ApprovalTicket
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DecideApproval approves (or rejects) a ticket.
func (c *Client) DecideApproval(ctx context.Context, id string, approved bool, by string) (*ApprovalTicket, error) {
	body := map[string]interface{}{"approved": approved, "by": by}
	var out ApprovalTicket
	if err := c.doJSON(ctx, http.MethodPost, "/api/approvals/"+url.PathEscape(id)+"/decide", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EditApproval amends a pending ticket's params.
func (c *Client) EditApproval(ctx context.Context, id string, params map[string]interface{}, reason string) (*ApprovalTicket, error) {
	body := map[string]interface{}{"params": params, "reason": reason}
	var out ApprovalTicket
	if err := c.doJSON(ctx, http.MethodPost, "/api/approvals/"+url.PathEscape(id)+"/edit", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- /api/identity ---

// MintToken mints a scoped, short-lived token for a task.
func (c *Client) MintToken(ctx context.Context, task string, scopes []string, ttl string) (token string, expiresAt string, err error) {
	body := map[string]interface{}{"scopes": scopes, "ttl": ttl}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/identity/"+url.PathEscape(task)+"/tokens", body, &out); err != nil {
		return "", "", err
	}
	return out.Token, out.ExpiresAt, nil
}

// RefreshToken rotates a token (old one is revoked).
func (c *Client) RefreshToken(ctx context.Context, token string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/identity/refresh", map[string]string{"token": token}, &out); err != nil {
		return "", err
	}
	return out.Token, nil
}

// RevokeAllTokens revokes every token minted for a task.
func (c *Client) RevokeAllTokens(ctx context.Context, task string) (int, error) {
	var out struct {
		Revoked int `json:"revoked"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/identity/"+url.PathEscape(task)+"/revoke", map[string]bool{"all": true}, &out); err != nil {
		return 0, err
	}
	return out.Revoked, nil
}

// --- /api/incidents ---

// IncidentRecord is one handled incident.
type IncidentRecord struct {
	TaskID   string `json:"task_id"`
	Severity string `json:"severity"`
	Signal   string `json:"signal"`
	Action   string `json:"action"`
	At       string `json:"at"`
	Error    string `json:"error,omitempty"`
}

// ReportIncident reports an anomaly to the incident controller.
func (c *Client) ReportIncident(ctx context.Context, task, severity, kind, detail string) (action string, err error) {
	body := map[string]string{"severity": severity, "kind": kind, "detail": detail}
	var out struct {
		Action string `json:"action"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/incidents/"+url.PathEscape(task)+"/report", body, &out); err != nil {
		return "", err
	}
	return out.Action, nil
}

// ListIncidents lists recently handled incidents.
func (c *Client) ListIncidents(ctx context.Context) ([]IncidentRecord, error) {
	var out []IncidentRecord
	if err := c.doJSON(ctx, http.MethodGet, "/api/incidents", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- /api/pool ---

// PoolStats is the warm pool occupancy.
type PoolStats struct {
	Ready   int `json:"ready"`
	Claimed int `json:"claimed"`
	Total   int `json:"total"`
}

// GetPoolStats fetches pool occupancy.
func (c *Client) GetPoolStats(ctx context.Context) (*PoolStats, error) {
	var out PoolStats
	if err := c.doJSON(ctx, http.MethodGet, "/api/pool/stats", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WarmPool pre-creates n sandboxes for a template.
func (c *Client) WarmPool(ctx context.Context, template string, n int) (created int, err error) {
	body := map[string]interface{}{"template": map[string]string{"name": template}, "n": n}
	var out struct {
		Created int `json:"created"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/pool/warm", body, &out); err != nil {
		return 0, err
	}
	return out.Created, nil
}

// --- metrics ---

// FetchMetrics pulls the Prometheus text exposition (bounded read).
func (c *Client) FetchMetrics(ctx context.Context) (string, error) {
	return c.fetchText(ctx, "/metrics")
}
