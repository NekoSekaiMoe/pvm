package api

// auth_test.go — multi-key registry + auth-callback delegation semantics
// (parse formats, local lookup, fail-closed callback, middleware headers).

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestParseKeyEntries(t *testing.T) {
	cases := []struct {
		blob string
		want []APIKey
	}{
		{"", nil},
		{"# comment only", nil},
		{"k1", []APIKey{{Key: "k1", Operator: "k1"}}},
		{"k1:alice", []APIKey{{Key: "k1", Operator: "alice"}}},
		{"k1:alice:tenant-a", []APIKey{{Key: "k1", Operator: "alice", Tenant: "tenant-a"}}},
		{"k1,k2:bob", []APIKey{{Key: "k1", Operator: "k1"}, {Key: "k2", Operator: "bob"}}},
		{"k1:alice\nk2\n\nk3:carol:t2", []APIKey{
			{Key: "k1", Operator: "alice"},
			{Key: "k2", Operator: "k2"},
			{Key: "k3", Operator: "carol", Tenant: "t2"},
		}},
		{"too:many:fields:here", nil}, // >3 fields skipped whole
		{":leadcolon", nil},           // empty key skipped
		{"key # inline note", nil},    // inner '#': malformed, skipped
		{"key\twith tabs", nil},       // inner whitespace: malformed, skipped
		{"k1, key # note, k2", []APIKey{{Key: "k1", Operator: "k1"}, {Key: "k2", Operator: "k2"}}}, // good entries survive a bad neighbor
	}
	for _, tc := range cases {
		t.Run(tc.blob, func(t *testing.T) {
			got := parseKeyEntries(tc.blob)
			if len(got) != len(tc.want) {
				t.Fatalf("parseKeyEntries(%q) = %+v, want %+v", tc.blob, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parseKeyEntries(%q)[%d] = %+v, want %+v", tc.blob, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestLoadKeyRegistryEnvAndFile(t *testing.T) {
	t.Setenv("API_SECRET", "master-key")
	t.Setenv("PVM_API_KEYS", "k1:alice:t1,k2")
	dir := t.TempDir()
	file := filepath.Join(dir, "keys")
	if err := os.WriteFile(file, []byte("# ops keys\nk3:bob\n\nk4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PVM_API_KEYS_FILE", file)

	reg := LoadKeyRegistry()
	for _, k := range []string{"master-key", "k1", "k2", "k3", "k4"} {
		if _, ok := reg.Lookup(k); !ok {
			t.Fatalf("key %q must be known", k)
		}
	}
	if _, ok := reg.Lookup("nope"); ok {
		t.Fatal("unknown key must not resolve")
	}
	if id, _ := reg.Lookup("k1"); id.Operator != "alice" || id.Tenant != "t1" {
		t.Fatalf("k1 identity = %+v", id)
	}
	if id, _ := reg.Lookup("master-key"); id.Operator != "master" {
		t.Fatalf("master operator = %q", id.Operator)
	}
}

func TestAuthenticateLocalFirst(t *testing.T) {
	// A callback that would deny everything proves local keys never hit it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	reg := &KeyRegistry{
		keys:     []APIKey{{Key: "local", Operator: "alice"}},
		callback: srv.URL,
	}
	id, err := reg.Authenticate("local", "/api/tasks", http.MethodGet)
	if err != nil || id.Operator != "alice" {
		t.Fatalf("local key must short-circuit: %+v %v", id, err)
	}
	if _, err := reg.Authenticate("unknown", "/api/tasks", http.MethodGet); err != ErrAuthDenied {
		t.Fatalf("callback 403 must deny, got %v", err)
	}
}

func TestAuthenticateCallbackDelegation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Reject one specific key; allow the rest with an actor header.
		buf, _ := io.ReadAll(r.Body)
		body := string(buf)
		switch {
		case strings.Contains(body, "reject-me"):
			w.WriteHeader(http.StatusUnauthorized)
		case strings.Contains(body, "\"path\":\"/api/pool/quota\""):
			w.Header().Set("X-PVM-Actor", "idp-bob")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	reg := &KeyRegistry{callback: srv.URL}
	if _, err := reg.Authenticate("reject-me", "/x", "GET"); err != ErrAuthDenied {
		t.Fatalf("callback 401 must map to ErrAuthDenied, got %v", err)
	}
	id, err := reg.Authenticate("ok-key", "/api/pool/quota", "GET")
	if err != nil || id.Operator != "idp-bob" {
		t.Fatalf("callback allow with actor header: %+v %v", id, err)
	}
	id, err = reg.Authenticate("ok-key", "/other", "GET")
	if err != nil || id.Operator != "callback" {
		t.Fatalf("callback allow default actor: %+v %v", id, err)
	}
}

func TestAuthenticateCallbackUnavailableFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("listener closed after this")
	}))
	url := srv.URL
	srv.Close() // unreachable now

	reg := &KeyRegistry{callback: url}
	_, err := reg.Authenticate("any", "/x", "GET")
	if err == nil || err.Error() == "" || !strings.Contains(err.Error(), ErrAuthUnavailable.Error()) {
		t.Fatalf("unreachable callback must fail closed with ErrAuthUnavailable, got %v", err)
	}
}

func TestKeyAuthMiddlewareHeadersAndCodes(t *testing.T) {
	e := echo.New()
	reg := &KeyRegistry{keys: []APIKey{{Key: "sekrit", Operator: "alice", Tenant: "t1"}}}
	e.GET("/api/who", func(c echo.Context) error {
		actor, _ := c.Get("actor").(string)
		tenant, _ := c.Get("tenant").(string)
		return c.JSON(http.StatusOK, map[string]string{"actor": actor, "tenant": tenant})
	}, keyAuthMiddleware(reg))

	// Bearer header.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/who", nil)
	req.Header.Set("Authorization", "Bearer sekrit")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("bearer auth failed: %d %s", rec.Code, rec.Body.String())
	}

	// X-API-KEY header.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/who", nil)
	req.Header.Set("X-API-KEY", "sekrit")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("X-API-KEY auth failed: %d", rec.Code)
	}

	// Wrong key: 401.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/who", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key must 401, got %d", rec.Code)
	}

	// No key: 401.
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/who", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing key must 401, got %d", rec.Code)
	}
}

func TestKeyAuthMiddlewareBrokenCallbackIs500(t *testing.T) {
	e := echo.New()
	reg := &KeyRegistry{callback: "http://127.0.0.1:1/callback"} // unreachable
	e.GET("/api/x", func(c echo.Context) error { return c.NoContent(http.StatusOK) }, keyAuthMiddleware(reg))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set("Authorization", "Bearer anything")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("broken callback must fail closed as 500, got %d", rec.Code)
	}
}

func TestRequestKeyBearerFormRequiresSeparator(t *testing.T) {
	cases := []struct {
		auth string
		want string
	}{
		{"Bearer sekrit", "sekrit"},  // canonical form
		{"Bearer  spaced", "spaced"}, // extra whitespace trimmed
		{"Bearerxyz", "Bearerxyz"},   // no separator: bare credential, stays whole
		{"Bearer", "Bearer"},         // bare scheme word is a (wrong) credential
		{"", ""},                     // falls through to X-API-KEY below
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		req.Header.Set("X-API-KEY", "xk")
		want := tc.want
		if want == "" {
			want = "xk"
		}
		if got := requestKey(req); got != want {
			t.Fatalf("requestKey(%q) = %q, want %q", tc.auth, got, want)
		}
	}
}

func TestSecureCallbackCleartextRule(t *testing.T) {
	// Deterministic resolver: the "localhost" case must not depend on the
	// host machine's /etc/hosts.
	orig := lookupHost
	defer func() { lookupHost = orig }()
	lookupHost = func(string) ([]string, error) { return []string{"127.0.0.1"}, nil }

	cases := []struct {
		name     string
		callback string
		optin    string
		want     string
	}{
		{"empty stays empty", "", "", ""},
		{"https allowed", "https://idp.example/auth", "", "https://idp.example/auth"},
		{"loopback http allowed", "http://127.0.0.1:9999/auth", "", "http://127.0.0.1:9999/auth"},
		{"localhost http allowed", "http://localhost:9999/auth", "", "http://localhost:9999/auth"},
		{"remote http refused", "http://idp.example/auth", "", ""},
		{"remote http refused with other optin", "http://idp.example/auth", "yes", ""},
		{"remote http explicit opt-in", "http://idp.example/auth", "1", "http://idp.example/auth"},
		{"garbage url refused", "://bad", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PVM_AUTH_CALLBACK_ALLOW_HTTP", tc.optin)
			if got := secureCallback(tc.callback); got != tc.want {
				t.Fatalf("secureCallback(%q) = %q, want %q", tc.callback, got, tc.want)
			}
		})
	}
}

func TestAuthenticateCallbackRedirectRefused(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/leak", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	// Directly-built registry (client==nil path) must be just as hardened:
	// the fallback client also refuses to replay the raw-key body.
	reg := &KeyRegistry{callback: redirector.URL}
	if _, err := reg.Authenticate("some-key", "/x", "GET"); err != ErrAuthDenied {
		t.Fatalf("redirected callback must deny, got %v", err)
	}
	if reached {
		t.Fatal("callback redirect must never be followed (raw key would leak)")
	}
}

// "localhost" is only a name: the callback must be refused when the
// resolver points it at a non-loopback address (fail closed), and only
// accepted when EVERY resolved address is loopback.
func TestSecureCallbackLocalhostResolution(t *testing.T) {
	orig := lookupHost
	defer func() { lookupHost = orig }()

	cases := []struct {
		name  string
		ips   []string
		lerr  error
		optin string
		want  string
	}{
		{"all loopback allows http", []string{"127.0.0.1", "::1"}, nil, "", "http://localhost:9999/auth"},
		{"non-loopback resolution refuses", []string{"10.0.0.9"}, nil, "", ""},
		{"mixed resolution refuses", []string{"127.0.0.1", "192.0.2.5"}, nil, "", ""},
		{"resolver failure refuses (fail closed)", nil, fmt.Errorf("dns broken"), "", ""},
		{"explicit opt-in overrides resolution", []string{"10.0.0.9"}, nil, "1", "http://localhost:9999/auth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PVM_AUTH_CALLBACK_ALLOW_HTTP", tc.optin)
			lookupHost = func(string) ([]string, error) { return tc.ips, tc.lerr }
			if got := secureCallback("http://localhost:9999/auth"); got != tc.want {
				t.Fatalf("secureCallback = %q, want %q", got, tc.want)
			}
		})
	}
}
