// Package sdk is a thin Go client for PVM's REST API, mirroring
// ref/sdk/go (CubeSandbox) surface at single-host scale. It talks to
// PVM's /api/* endpoints directly; callers point it at the PVM host.
package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	APIURL     string
	APIKey     string
	TemplateID string
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
	return &Client{cfg: cfg, http: &http.Client{}}
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
	VolumeID  string `json:"volume_id"`
	Name      string `json:"name"`
	Driver    string `json:"driver"`
	RefCount  int    `json:"refcount"`
	CreatedAt string `json:"created_at"`
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
	TemplateID string `json:"template_id"`
	Alias      string `json:"alias"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	ImageRef   string `json:"image_ref"`
	CreatedAt  string `json:"created_at"`
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
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sdk: %s %s -> %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}
