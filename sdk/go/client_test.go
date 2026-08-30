package sdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	c, err := NewClient(Config{APIURL: ts.URL + "/", APIKey: "test-key"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
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
			c, err := NewClient(Config{Timeout: tt.timeout})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
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
	c, err := NewClient(Config{APIURL: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
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
	c, err := NewClient(Config{APIURL: ts.URL, Timeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	start := time.Now()
	_, err = c.ListVolumes(context.Background())
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
	c, err := NewClient(Config{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestNewClient_SchemePolicy pins the transport policy: plaintext http is
// only accepted for loopback hosts (localhost, 127.0.0.0/8, ::1); anything
// else must be https so Bearer credentials never cross in cleartext.
func TestNewClient_SchemePolicy(t *testing.T) {
	tests := []struct {
		name    string
		apiURL  string
		wantErr string
	}{
		{"http loopback ok", "http://127.0.0.1:3000", ""},
		{"http any 127/8 ok", "http://127.200.1.1:9", ""},
		{"http localhost ok", "http://localhost:3000", ""},
		{"http ipv6 loopback ok", "http://[::1]:3000", ""},
		{"empty defaults to loopback http ok", "", ""},
		{"https remote ok", "https://pvm.example.com", ""},
		{
			"http remote rejected", "http://pvm.example.com:8080",
			`refusing plaintext http to non-loopback host "pvm.example.com"`,
		},
		{"http private ip rejected", "http://10.0.0.5:3000", "refusing plaintext http"},
		{"ftp scheme rejected", "ftp://pvm.example.com", "unsupported API URL scheme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(Config{APIURL: tt.apiURL})
			if c != nil {
				defer c.Close()
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewClient(%q) = %v, want nil error", tt.apiURL, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewClient(%q) error = %v, want containing %q", tt.apiURL, err, tt.wantErr)
			}
		})
	}
}

// TestClient_RedirectNoPlaintextDowngrade verifies CheckRedirect: a redirect
// from an allowed origin to a non-loopback http target aborts the chain,
// while redirects that stay on loopback http are followed normally.
func TestClient_RedirectNoPlaintextDowngrade(t *testing.T) {
	t.Run("downgrade to non-loopback http blocked", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://pvm.example.com:9/api/volumes", http.StatusFound)
		}))
		t.Cleanup(ts.Close)
		c, err := NewClient(Config{APIURL: ts.URL, APIKey: "k"})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		_, err = c.ListVolumes(context.Background())
		if err == nil || !strings.Contains(err.Error(), "refusing plaintext http") {
			t.Fatalf("ListVolumes error = %v, want redirect downgrade to be blocked", err)
		}
	})

	t.Run("loopback to loopback redirect followed", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/volumes":
				http.Redirect(w, r, "/api/volumes-2", http.StatusFound)
			case "/api/volumes-2":
				writeJSON(t, w, http.StatusOK, "["+volumeJSON+"]")
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(ts.Close)
		c, err := NewClient(Config{APIURL: ts.URL})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		got, err := c.ListVolumes(context.Background())
		if err != nil {
			t.Fatalf("ListVolumes: %v", err)
		}
		if len(got) != 1 || got[0].VolumeID != "vol-1" {
			t.Fatalf("unexpected list after redirect: %+v", got)
		}
	})
}

// TestCreateSandbox_TimeoutValidation covers the three-value timeout
// semantics: values below the NeverTimeout (-1) sentinel are rejected before
// any query string is written; -1, 0 and positive values pass through.
func TestCreateSandbox_TimeoutValidation(t *testing.T) {
	tests := []struct {
		name      string
		timeout   int
		wantErr   string
		wantQuery string
	}{
		{"below sentinel rejected", -2, "-2 is invalid", ""},
		{"far below sentinel rejected", -100, "-100 is invalid", ""},
		{"never timeout sentinel ok", NeverTimeout, "", "-1"},
		{"positive ttl ok", 300, "", "300"},
		{"zero means server default", 0, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hit int32
			var gotQuery string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.StoreInt32(&hit, 1)
				gotQuery = r.URL.Query().Get("timeout")
				writeJSON(t, w, http.StatusOK, `{"sandboxID":"sbx-1","templateID":"tpl-1"}`)
			}))
			t.Cleanup(ts.Close)
			c, err := NewClient(Config{APIURL: ts.URL})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			t.Cleanup(func() { c.Close() })

			_, err = c.CreateSandbox(context.Background(), CreateSandboxOptions{Template: "tpl-1", TimeoutSeconds: tt.timeout})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("CreateSandbox(timeout=%d) error = %v, want containing %q", tt.timeout, err, tt.wantErr)
				}
				if atomic.LoadInt32(&hit) != 0 {
					t.Fatalf("rejected timeout must not reach the server")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateSandbox(timeout=%d): %v", tt.timeout, err)
			}
			if gotQuery != tt.wantQuery {
				t.Fatalf("timeout query = %q, want %q", gotQuery, tt.wantQuery)
			}
		})
	}
}

// TestWaitForTemplateReady_TimeoutBoundsPolls verifies the wait timeout is
// threaded into every poll request: a hanging endpoint cannot stretch the
// wait past the deadline anymore.
func TestWaitForTemplateReady_TimeoutBoundsPolls(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { close(release); ts.Close() })
	c, err := NewClient(Config{APIURL: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	start := time.Now()
	_, err = c.WaitForTemplateReady(context.Background(), "tpl-1", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout not applied to in-flight request: took %v", elapsed)
	}
}

// TestWaitForTemplateReady_PollsUntilDone covers the happy path: non-terminal
// phases keep polling (300ms gap) until a terminal phase arrives.
func TestWaitForTemplateReady_PollsUntilDone(t *testing.T) {
	var polls atomic.Int32
	c, recs := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if n := polls.Add(1); n < 2 {
			writeJSON(t, w, http.StatusOK, `{"phase":"building","pct":10,"log_tail":"tick"}`)
			return
		}
		writeJSON(t, w, http.StatusOK, `{"phase":"done","pct":100,"log_tail":""}`)
	})
	st, err := c.WaitForTemplateReady(context.Background(), "tpl-1", 10*time.Second)
	if err != nil {
		t.Fatalf("WaitForTemplateReady: %v", err)
	}
	if st.Phase != "done" || st.Pct != 100 {
		t.Fatalf("unexpected status: %+v", st)
	}
	if got := polls.Load(); got != 2 {
		t.Fatalf("polls = %d, want 2", got)
	}
	if rs := recs(); len(rs) != 2 || rs[0].path != "/api/templates/tpl-1/build" {
		t.Fatalf("requests = %+v, want two GET /api/templates/tpl-1/build", rs)
	}
}

// newEnvdTestServer spins up an httptest server and returns an EnvdClient
// pointing at it via the real NewEnvdClient constructor (so scheme, port
// and redirect policy are all exercised): ts.URL's host:port is loopback,
// hence http, and its explicit port must be preserved verbatim.
func newEnvdTestServer(t *testing.T, h http.HandlerFunc) *EnvdClient {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse %s: %v", ts.URL, err)
	}
	e := NewEnvdClient(u.Host, "task-1")
	if e.base != ts.URL {
		t.Fatalf("client base = %q, want %q", e.base, ts.URL)
	}
	return e
}

// TestNewEnvdClient_SchemeSelection pins the envd transport policy: loopback
// hosts speak plain http (envd convention), everything else https. It also
// pins port handling: only a port-less host gets DefaultEnvdPort appended;
// a caller-supplied port ("host:port" or "[v6]:port") is kept verbatim —
// previously the default port was blindly appended, producing
// "127.0.0.1:9000:49983".
func TestNewEnvdClient_SchemeSelection(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"empty defaults to loopback http", "", "http://127.0.0.1:49983"},
		{"loopback ipv4 http", "127.0.0.1", "http://127.0.0.1:49983"},
		{"any 127/8 http", "127.200.1.1", "http://127.200.1.1:49983"},
		{"localhost http", "localhost", "http://localhost:49983"},
		{"ipv6 loopback http", "[::1]", "http://[::1]:49983"},
		{"remote host https", "example.com", "https://example.com:49983"},
		{"loopback with port keeps it", "127.0.0.1:9000", "http://127.0.0.1:9000"},
		{"localhost with port keeps it", "localhost:9000", "http://localhost:9000"},
		{"ipv6 loopback with port keeps it", "[::1]:9000", "http://[::1]:9000"},
		{"remote with port keeps https and port", "sandbox.example.com:8443", "https://sandbox.example.com:8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEnvdClient(tt.host, "task-1").base; got != tt.want {
				t.Fatalf("NewEnvdClient(%q).base = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

// TestEnvdClient_WriteFileStatus verifies >= 400 responses surface as errors
// carrying the path and status code (previously silently returned nil).
func TestEnvdClient_WriteFileStatus(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr string
	}{
		{"created ok", http.StatusOK, ""},
		{"bad request surfaced", http.StatusBadRequest, "envd: write /tmp/f -> 400"},
		{"server error surfaced", http.StatusInternalServerError, "envd: write /tmp/f -> 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnvdTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			})
			err := e.WriteFile(context.Background(), "/tmp/f", []byte("data"))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("WriteFile error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestEnvdClient_RunOutputCap streams 5x16 MiB stdout events (80 MiB total)
// through a fake envd server: Run must abort once the accumulated
// stdout+stderr exceeds maxRunOutputBytes instead of buffering unbounded.
func TestEnvdClient_RunOutputCap(t *testing.T) {
	const chunk = 16 << 20 // 16 MiB raw -> ~21 MiB base64, under the 32 MiB frame cap
	e := newEnvdTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/connect+json")
		b64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), chunk))
		for i := 0; i < 5; i++ { // 5 * 16 MiB = 80 MiB > 64 MiB cap
			payload, _ := json.Marshal(map[string]any{
				"event": map[string]any{"data": map[string]string{"stdout": b64}},
			})
			_, _ = w.Write(EncodeEnvelope(payload, 0))
		}
		end, _ := json.Marshal(map[string]any{})
		_, _ = w.Write(EncodeEnvelope(end, ConnectEndStreamFlag))
	})
	_, err := e.Run(context.Background(), "cat /dev/zero", nil)
	if err == nil {
		t.Fatal("Run: expected output-limit error, got nil")
	}
	for _, want := range []string{"run output exceeded limit", "83886080", fmt.Sprint(maxRunOutputBytes)} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Run error = %q, want containing %q", err.Error(), want)
		}
	}
}

// TestEnvdClient_RedirectRejected pins that envd clients never follow HTTP
// redirects. 307/308 preserve method+body, so a server answering with such
// a status and a Location header must surface as an explicit error instead
// of Go silently replaying Run's command/envs envelope to the (possibly
// untrusted, possibly cleartext) redirect target. Server A redirects to
// server B; B's handler must never be hit.
func TestEnvdClient_RedirectRejected(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			var bHits atomic.Int32
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bHits.Add(1)
			}))
			t.Cleanup(b.Close)

			e := newEnvdTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, b.URL+"/sink", status)
			})

			_, err := e.Run(context.Background(), "echo secret-marker", map[string]string{"TOKEN": "leak-me"})
			if err == nil || !strings.Contains(err.Error(), "redirect") {
				t.Fatalf("Run error = %v, want error mentioning redirect", err)
			}
			if got := bHits.Load(); got != 0 {
				t.Fatalf("redirect target was hit %d times, want 0 (request body must not be replayed)", got)
			}
		})
	}
}
