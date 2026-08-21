package sdk

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// created is a fixed timestamp serialized as RFC3339 in test payloads; the
// client must decode it back into an equal time.Time (CreatedAt fields).
var created = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

const (
	volumeJSON   = `{"volume_id":"vol-1","name":"data","driver":"builtin","refcount":1,"created_at":"2025-01-02T03:04:05Z"}`
	templateJSON = `{"template_id":"tpl-1","alias":"base","kind":"rootfs","status":"READY","image_ref":"img:1","created_at":"2025-01-02T03:04:05Z"}`
)

// reqRecord captures what one client request looked like server-side.
// path uses URL.EscapedPath() so slash-containing ids stay visible as %2F.
type reqRecord struct {
	method string
	path   string
	auth   string
}

// newTestServer spins up an httptest server wrapping h, recording every
// request, and returns a Client pointed at it. The APIURL is deliberately
// given a trailing slash so every subtest also exercises normalization.
func newTestServer(t *testing.T, h http.HandlerFunc) (*Client, func() []reqRecord) {
	t.Helper()
	var (
		mu   sync.Mutex
		recs []reqRecord
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recs = append(recs, reqRecord{method: r.Method, path: r.URL.EscapedPath(), auth: r.Header.Get("Authorization")})
		mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	c := NewClient(Config{APIURL: ts.URL + "/", APIKey: "test-key"})
	t.Cleanup(func() { c.Close() })
	snapshot := func() []reqRecord {
		mu.Lock()
		defer mu.Unlock()
		return append([]reqRecord(nil), recs...)
	}
	return c, snapshot
}

// writeJSON writes status with a JSON body.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func TestNewConfigFromEnv(t *testing.T) {
	unset := func(t *testing.T, keys ...string) {
		t.Helper()
		for _, k := range keys {
			old, ok := os.LookupEnv(k)
			if err := os.Unsetenv(k); err != nil {
				t.Fatalf("unset %s: %v", k, err)
			}
			if ok {
				t.Cleanup(func() { os.Setenv(k, old) })
			}
		}
	}
	all := []string{"PVM_API_URL", "CUBE_API_URL", "PVM_API_KEY", "CUBE_API_KEY", "PVM_TEMPLATE_ID"}

	tests := []struct {
		name    string
		set     map[string]string
		wantCfg Config
	}{
		{
			name: "defaults",
			set:  map[string]string{},
			wantCfg: Config{
				APIURL: "http://127.0.0.1:3000",
			},
		},
		{
			name: "pvm url and key preferred",
			set: map[string]string{
				"PVM_API_URL": "http://pvm:9", "CUBE_API_URL": "http://cube:9",
				"PVM_API_KEY": "pvm-key", "CUBE_API_KEY": "cube-key",
				"PVM_TEMPLATE_ID": "tpl-1",
			},
			wantCfg: Config{APIURL: "http://pvm:9", APIKey: "pvm-key", TemplateID: "tpl-1"},
		},
		{
			name: "cube url and key fallback",
			set: map[string]string{
				"CUBE_API_URL": "http://cube:9", "CUBE_API_KEY": "cube-key",
			},
			wantCfg: Config{APIURL: "http://cube:9", APIKey: "cube-key"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unset(t, all...)
			for k, v := range tt.set {
				t.Setenv(k, v)
			}
			got := NewConfigFromEnv()
			if got != tt.wantCfg {
				t.Fatalf("NewConfigFromEnv() = %+v, want %+v", got, tt.wantCfg)
			}
		})
	}
}

func TestNewClient_TimeoutDefaults(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"zero uses default", 0, DefaultTimeout},
		{"negative uses default", -1, DefaultTimeout},
		{"override wins", 5 * time.Second, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(Config{Timeout: tt.timeout})
			defer c.Close()
			if got := c.http.Timeout; got != tt.want {
				t.Fatalf("client timeout = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestClient_Volumes covers every public volume method end to end against an
// httptest server: URL trailing-slash normalization, the Authorization
// header, PathEscape'd ids, and JSON decoding into time.Time CreatedAt.
func TestClient_Volumes(t *testing.T) {
	c, recs := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/volumes":
			writeJSON(t, w, http.StatusOK, volumeJSON)
		case r.Method == http.MethodGet && r.URL.Path == "/api/volumes":
			writeJSON(t, w, http.StatusOK, "["+volumeJSON+"]")
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/api/volumes/empty":
			w.WriteHeader(http.StatusOK) // zero-byte body
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/volumes/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/volumes/")
			writeJSON(t, w, http.StatusOK, fmt.Sprintf(`{"volume_id":%q,"name":"data","driver":"builtin","refcount":1,"created_at":"2025-01-02T03:04:05Z"}`, id))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent) // empty body
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()

	t.Run("CreateVolume", func(t *testing.T) {
		got, err := c.CreateVolume(ctx, CreateVolumeOptions{Name: "data", Driver: "builtin"})
		if err != nil {
			t.Fatalf("CreateVolume: %v", err)
		}
		if got.VolumeID != "vol-1" || got.RefCount != 1 {
			t.Fatalf("unexpected volume: %+v", got)
		}
		if !got.CreatedAt.Equal(created) {
			t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, created)
		}
		rs := recs()
		if len(rs) != 1 || rs[0].method != http.MethodPost || rs[0].path != "/api/volumes" {
			t.Fatalf("request = %+v, want POST /api/volumes (normalized, no double slash)", rs)
		}
		if rs[0].auth != "Bearer test-key" {
			t.Fatalf("Authorization = %q, want %q", rs[0].auth, "Bearer test-key")
		}
	})

	t.Run("ListVolumes", func(t *testing.T) {
		got, err := c.ListVolumes(ctx)
		if err != nil {
			t.Fatalf("ListVolumes: %v", err)
		}
		if len(got) != 1 || got[0].VolumeID != "vol-1" {
			t.Fatalf("unexpected list: %+v", got)
		}
		if !got[0].CreatedAt.Equal(created) {
			t.Fatalf("CreatedAt = %v, want %v", got[0].CreatedAt, created)
		}
	})

	t.Run("GetVolume escapes slash id", func(t *testing.T) {
		got, err := c.GetVolume(ctx, "team/a")
		if err != nil {
			t.Fatalf("GetVolume: %v", err)
		}
		if got.VolumeID != "team/a" {
			t.Fatalf("VolumeID = %q, want %q", got.VolumeID, "team/a")
		}
		rs := recs()
		if len(rs) == 0 || rs[len(rs)-1].path != "/api/volumes/team%2Fa" {
			t.Fatalf("path = %+v, want /api/volumes/team%%2Fa (PathEscape)", rs)
		}
	})

	t.Run("GetVolume empty body succeeds", func(t *testing.T) {
		got, err := c.GetVolume(ctx, "empty")
		if err != nil {
			t.Fatalf("GetVolume(empty body): %v, want nil (io.EOF treated as empty success)", err)
		}
		if got == nil || got.VolumeID != "" {
			t.Fatalf("expected zero-value VolumeInfo, got %+v", got)
		}
	})

	t.Run("DeleteVolume", func(t *testing.T) {
		if err := c.DeleteVolume(ctx, "vol-1"); err != nil {
			t.Fatalf("DeleteVolume: %v", err)
		}
		rs := recs()
		if len(rs) == 0 || rs[len(rs)-1].method != http.MethodDelete || rs[len(rs)-1].path != "/api/volumes/vol-1" {
			t.Fatalf("request = %+v, want DELETE /api/volumes/vol-1", rs)
		}
	})
}

// TestClient_NoAuthHeaderWhenNoKey verifies the Authorization header is
// omitted entirely when Config.APIKey is empty.
func TestClient_NoAuthHeaderWhenNoKey(t *testing.T) {
	var (
		mu   sync.Mutex
		auth = "<unset>"
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		writeJSON(t, w, http.StatusOK, "["+volumeJSON+"]")
	}))
	t.Cleanup(ts.Close)
	c := NewClient(Config{APIURL: ts.URL})
	t.Cleanup(func() { c.Close() })
	if _, err := c.ListVolumes(context.Background()); err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if auth != "" {
		t.Fatalf("Authorization header = %q, want empty", auth)
	}
}

// TestClient_Templates covers every public template method.
func TestClient_Templates(t *testing.T) {
	c, recs := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/templates":
			writeJSON(t, w, http.StatusOK, templateJSON)
		case r.Method == http.MethodGet && r.URL.Path == "/api/templates":
			writeJSON(t, w, http.StatusOK, "["+templateJSON+"]")
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/alias"):
			writeJSON(t, w, http.StatusOK, templateJSON)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/templates/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/templates/")
			writeJSON(t, w, http.StatusOK, fmt.Sprintf(`{"template_id":%q,"alias":"base","kind":"rootfs","status":"READY","image_ref":"img:1","created_at":"2025-01-02T03:04:05Z"}`, id))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()

	t.Run("CreateTemplate", func(t *testing.T) {
		got, err := c.CreateTemplate(ctx, "img:1", "base")
		if err != nil {
			t.Fatalf("CreateTemplate: %v", err)
		}
		if got.TemplateID != "tpl-1" || got.Alias != "base" {
			t.Fatalf("unexpected template: %+v", got)
		}
		if !got.CreatedAt.Equal(created) {
			t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, created)
		}
	})

	t.Run("ListTemplates", func(t *testing.T) {
		got, err := c.ListTemplates(ctx)
		if err != nil {
			t.Fatalf("ListTemplates: %v", err)
		}
		if len(got) != 1 || got[0].TemplateID != "tpl-1" {
			t.Fatalf("unexpected list: %+v", got)
		}
	})

	t.Run("GetTemplate escapes slash id", func(t *testing.T) {
		got, err := c.GetTemplate(ctx, "a/b")
		if err != nil {
			t.Fatalf("GetTemplate: %v", err)
		}
		if got.TemplateID != "a/b" {
			t.Fatalf("TemplateID = %q, want %q", got.TemplateID, "a/b")
		}
		rs := recs()
		if len(rs) == 0 || rs[len(rs)-1].path != "/api/templates/a%2Fb" {
			t.Fatalf("path = %+v, want /api/templates/a%%2Fb (PathEscape)", rs)
		}
	})

	t.Run("SetTemplateAlias escapes slash id", func(t *testing.T) {
		got, err := c.SetTemplateAlias(ctx, "a/b", "new")
		if err != nil {
			t.Fatalf("SetTemplateAlias: %v", err)
		}
		if got.TemplateID != "tpl-1" {
			t.Fatalf("unexpected template: %+v", got)
		}
		rs := recs()
		if len(rs) == 0 || rs[len(rs)-1].method != http.MethodPost || rs[len(rs)-1].path != "/api/templates/a%2Fb/alias" {
			t.Fatalf("request = %+v, want POST /api/templates/a%%2Fb/alias", rs)
		}
	})

	t.Run("DeleteTemplate", func(t *testing.T) {
		if err := c.DeleteTemplate(ctx, "tpl-1"); err != nil {
			t.Fatalf("DeleteTemplate: %v", err)
		}
	})
}

// TestClient_ErrorMapping verifies 4xx/5xx responses surface as errors that
// carry the method, the (unescaped) path, the status code and the body.
func TestClient_ErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"bad request 400", http.StatusBadRequest},
		{"not found 404", http.StatusNotFound},
		{"server error 500", http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, "boom")
			})
			_, err := c.GetVolume(context.Background(), "vol-1")
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", tt.status)
			}
			want := fmt.Sprintf("sdk: GET /api/volumes/vol-1 -> %d: boom", tt.status)
			if err.Error() != want {
				t.Fatalf("error = %q, want %q", err.Error(), want)
			}
		})
	}
}

// TestClient_TimeoutApplied drives a request against a stalled endpoint with
// a tiny Config.Timeout: the client's http timeout must fire (url.Error with
// Timeout() true) instead of blocking forever.
func TestClient_TimeoutApplied(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { close(release); ts.Close() })
	c := NewClient(Config{APIURL: ts.URL, Timeout: 10 * time.Millisecond})
	t.Cleanup(func() { c.Close() })

	start := time.Now()
	_, err := c.ListVolumes(context.Background())
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout not applied: request took %v", elapsed)
	}
	ue, ok := err.(*url.Error)
	if !ok || !ue.Timeout() {
		t.Fatalf("error = %T (%v), want *url.Error with Timeout()=true", err, err)
	}
}

func TestClient_Close(t *testing.T) {
	c := NewClient(Config{})
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
