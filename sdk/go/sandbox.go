package sdk

// sandbox.go — E2B-compatible lifecycle surface (root-level /sandboxes,
// X-API-KEY auth): list/create/kill/refresh (=setTimeout), with the
// NEVER_TIMEOUT sentinel from the CubeSandbox semantics.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// NeverTimeout is the -1 sentinel: the sandbox is never reclaimed on idle.
const NeverTimeout int = -1

// SandboxInfo is the /sandboxes list row.
type SandboxInfo struct {
	SandboxID string            `json:"sandboxID"`
	Template  string            `json:"templateID"`
	Alias     string            `json:"alias,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Status    string            `json:"status,omitempty"`
	StartedAt string            `json:"startedAt,omitempty"`
	EndAt     string            `json:"endAt,omitempty"`
}

// CreateSandboxOptions shapes POST /sandboxes query params.
type CreateSandboxOptions struct {
	// Template is a template id; Alias addresses by alias instead.
	Template string
	Alias    string
	// TimeoutSeconds follows the three-value semantics: 0/unset = server
	// default, NeverTimeout (-1) = never, N>0 = idle TTL seconds.
	TimeoutSeconds int
	Metadata       map[string]string
}

// ListSandboxes lists sandboxes visible to the API key.
func (c *Client) ListSandboxes(ctx context.Context) ([]SandboxInfo, error) {
	var out []SandboxInfo
	if err := c.e2bJSON(ctx, http.MethodGet, "/sandboxes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateSandbox boots a sandbox from a template or alias.
func (c *Client) CreateSandbox(ctx context.Context, opts CreateSandboxOptions) (*SandboxInfo, error) {
	q := url.Values{}
	switch {
	case opts.Template != "":
		q.Set("template", opts.Template)
	case opts.Alias != "":
		q.Set("template", opts.Alias)
	default:
		return nil, fmt.Errorf("sdk: CreateSandbox requires Template or Alias")
	}
	if opts.TimeoutSeconds != 0 {
		q.Set("timeout", fmt.Sprint(opts.TimeoutSeconds))
	}
	for k, v := range opts.Metadata {
		q.Set("metadata_"+k, v)
	}
	var out SandboxInfo
	if err := c.e2bJSON(ctx, http.MethodPost, "/sandboxes?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// KillSandbox deletes a sandbox (idempotent server-side).
func (c *Client) KillSandbox(ctx context.Context, sandboxID string) error {
	return c.e2bJSON(ctx, http.MethodDelete, "/sandboxes/"+url.PathEscape(sandboxID), nil, nil)
}

// RefreshSandbox extends the sandbox deadline by duration seconds
// (setTimeout semantics).
func (c *Client) RefreshSandbox(ctx context.Context, sandboxID string, durationSeconds int) error {
	body := map[string]int{"duration": durationSeconds}
	return c.e2bJSON(ctx, http.MethodPost, "/sandboxes/"+url.PathEscape(sandboxID)+"/refreshes", body, nil)
}

// VersionInfo mirrors GET /version.
type VersionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Goos    string `json:"goos"`
	Goarch  string `json:"goarch"`
}

// Health pings GET /healthz (no auth).
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.APIURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sdk: healthz -> %d", resp.StatusCode)
	}
	return nil
}

// Version fetches build metadata (no auth).
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	var v VersionInfo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.APIURL+"/version", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("sdk: version -> %d: %s", resp.StatusCode, b)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

// e2bJSON performs a request against the E2B surface: root paths, X-API-KEY
// header (the official SDK convention).
func (c *Client) e2bJSON(ctx context.Context, method, path string, body any, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.APIURL+path, bytesOrNil(raw, body))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.cfg.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeInto(resp, out)
}
