// Package sdk is a thin Go client for PVM's REST API, mirroring
// ref/sdk/go (CubeSandbox) surface at single-host scale. It talks to
// PVM's /api/* endpoints directly; callers point it at the PVM host.
package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// DefaultTimeout is the http.Client timeout applied when Config.Timeout
	// is zero.
	DefaultTimeout = 30 * time.Second

	// maxResponseBodyBytes bounds every response body read (error bodies and
	// JSON decoding alike) so a hostile endpoint cannot exhaust memory.
	maxResponseBodyBytes = 1 << 20 // 1 MiB
)

type Config struct {
	APIURL     string
	APIKey     string
	TemplateID string

	// Timeout is the per-request http.Client timeout. Zero means
	// DefaultTimeout (30s); a positive value takes precedence.
	Timeout time.Duration
}

func NewConfigFromEnv() Config {
	apiURL := os.Getenv("PVM_API_URL")
	if apiURL == "" {
		apiURL = os.Getenv("CUBE_API_URL")
	}
	if apiURL == "" {
		apiURL = "http://127.0.0.1:3000"
	}
	apiKey := os.Getenv("PVM_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("CUBE_API_KEY")
	}
	return Config{APIURL: apiURL, APIKey: apiKey, TemplateID: os.Getenv("PVM_TEMPLATE_ID")}
}

type Client struct {
	cfg  Config
	http *http.Client
}

func NewClient(cfg Config) *Client {
	if cfg.APIURL == "" {
		cfg.APIURL = "http://127.0.0.1:3000"
	}
	// Normalize: a trailing slash would produce double slashes in every
	// joined path (e.g. "http://h:1//api/volumes").
	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: timeout}}
}

func (c *Client) Close() error {
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
	return nil
}

// --- Volumes ---

type VolumeMount struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Driver   string `json:"driver,omitempty"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

type CreateVolumeOptions struct {
	Name   string `json:"name"`
	Driver string `json:"driver,omitempty"`
}

// VolumeInfo is the API-facing volume shape. Token and PrivateData are
// deliberately absent: they are mount-plugin credentials and the API never
// returns them.
type VolumeInfo struct {
	VolumeID  string    `json:"volume_id"`
	Name      string    `json:"name"`
	Driver    string    `json:"driver"`
	RefCount  int       `json:"refcount"`
	CreatedAt time.Time `json:"created_at"`
}

func (c *Client) CreateVolume(ctx context.Context, opts CreateVolumeOptions) (*VolumeInfo, error) {
	var out VolumeInfo
	if err := c.doJSON(ctx, http.MethodPost, "/api/volumes", opts, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListVolumes(ctx context.Context) ([]VolumeInfo, error) {
	var out []VolumeInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/volumes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetVolume(ctx context.Context, id string) (*VolumeInfo, error) {
	var out VolumeInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/volumes/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteVolume(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/volumes/"+url.PathEscape(id), nil, nil)
}

// --- Templates ---

type TemplateInfo struct {
	TemplateID string    `json:"template_id"`
	Alias      string    `json:"alias"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"`
	ImageRef   string    `json:"image_ref"`
	CreatedAt  time.Time `json:"created_at"`
}

func (c *Client) CreateTemplate(ctx context.Context, imageRef, alias string) (*TemplateInfo, error) {
	payload := map[string]string{"image_ref": imageRef, "alias": alias}
	var out TemplateInfo
	if err := c.doJSON(ctx, http.MethodPost, "/api/templates", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListTemplates(ctx context.Context) ([]TemplateInfo, error) {
	var out []TemplateInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/templates", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetTemplate(ctx context.Context, id string) (*TemplateInfo, error) {
	var out TemplateInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/templates/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SetTemplateAlias(ctx context.Context, id, alias string) (*TemplateInfo, error) {
	payload := map[string]string{"alias": alias}
	var out TemplateInfo
	err := c.doJSON(ctx, http.MethodPost,
		"/api/templates/"+url.PathEscape(id)+"/alias", payload, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteTemplate(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/templates/"+url.PathEscape(id), nil, nil)
}

// --- Tasks (existing) ---

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.APIURL+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeInto(resp, out)
}

// decodeInto is the shared response path: bounded reads, surfaced error
// bodies, empty-2xx tolerance.
func decodeInto(resp *http.Response, out any) error {
	// Bound every body read so a hostile endpoint cannot stream unbounded
	// bytes into memory (error messages included).
	respBody := io.LimitReader(resp.Body, maxResponseBodyBytes)
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(respBody)
		return fmt.Errorf("sdk: %s %s -> %d: %s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, string(b))
	}
	if out != nil {
		// Decode returns io.EOF for an empty (2xx) body — treat that as a
		// successful empty response, not a decode failure.
		if err := json.NewDecoder(respBody).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	}
	io.Copy(io.Discard, respBody)
	return nil
}

// bytesOrNil adapts a marshalled body to io.Reader for the e2b helpers.
func bytesOrNil(raw []byte, body any) io.Reader {
	if body == nil {
		return nil
	}
	return bytes.NewReader(raw)
}

// marshalJSON is the nil-safe marshal used by hand-built requests.
func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// readerOrNil wraps marshalled bytes (nil body stays nil).
func readerOrNil(raw []byte) io.Reader {
	if raw == nil {
		return nil
	}
	return bytes.NewReader(raw)
}

// fetchText GETs a text endpoint (metrics) with a bounded read and the
// standard auth header.
func (c *Client) fetchText(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.APIURL+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("sdk: GET %s -> %d: %s", path, resp.StatusCode, string(b))
	}
	return string(b), nil
}
