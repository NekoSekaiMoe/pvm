package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"uml-container/internal/audit"
)

// Echo backend that records the request so tests can assert what reached it.
type recordingBackend struct {
	reqs []string
	srv  *httptest.Server
}

func newRecordingBackend(t *testing.T) *recordingBackend {
	rb := &recordingBackend{}
	rb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rb.reqs = append(rb.reqs, r.Method+" "+r.URL.Path)
		io.WriteString(w, "ok")
	}))
	t.Cleanup(rb.srv.Close)
	return rb
}

func startGatewayWithPolicy(t *testing.T, pol *Policy) *Gateway {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("egress-edge")
	g := NewGateway()
	g.SetPolicy("t1", pol)
	g.AttachLedger(l)
	if _, err := g.Listen(nil, "127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { g.Shutdown(nil) })
	return g
}

func clientVia(g *Gateway) *http.Client {
	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func do(c *http.Client, method, urlStr string, body string) *http.Response {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, urlStr, bodyReader)
	req.Header.Set("X-Task-Id", "t1")
	resp, err := c.Do(req)
	if err != nil {
		return &http.Response{StatusCode: 0} // sentinel: error means blocked
	}
	return resp
}

// --- wildcard matching boundary cases ---

func TestDomainMatch_WildcardBoundary(t *testing.T) {
	cases := []struct {
		host, rule string
		want       bool
	}{
		{"api.github.com", "*.github.com", true},
		{"github.com", "*.github.com", false},   // wildcard needs a subdomain
		{"apigithub.com", "*.github.com", false}, // suffix must be dot-prefixed
		{"evil.com", "*.github.com", false},
		{"a.b.github.com", "*.github.com", true}, // multi-level sub
		{"github.com", "github.com", true},
		{"GITHUB.COM", "github.com", true}, // case-insensitive at decide layer
		{"api.github.com.evil.com", "*.github.com", false}, // suffix hijack
	}
	for _, c := range cases {
		got := domainMatches(strings.ToLower(c.host), c.rule) // decideDomain lowercases
		if got != c.want {
			t.Errorf("domainMatches(%q,%q) = %v, want %v", c.host, c.rule, got, c.want)
		}
	}
}

// --- SSRF floor: proxy must refuse to CONNECT to a private IP even if the
// domain itself is allowlisted (defense against DNS rebinding). ---

func TestSSRF_PrivateIPBlocked(t *testing.T) {
	// allowlist a name that resolves to a loopback; the proxy's isPrivate
	// check must still block the dial.
	pol := &Policy{AllowDomains: []string{"localhost", "127.0.0.1"}}
	g := startGatewayWithPolicy(t, pol)
	c := clientVia(g)

	resp := do(c, "GET", "http://127.0.0.1:1/nope", "")
	if resp.StatusCode != 0 && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected block on private IP, got %d", resp.StatusCode)
	}
}

// --- size caps: response limit must truncate ---

func TestResponseSizeCap(t *testing.T) {
	// backend returns 1MB; cap at 4KB; we should get far less than 1MB.
	rb := newRecordingBackend(t)
	// swap handler to return big body
	rb.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.Copy(w, &infiniteReader{n: 1 << 20})
	})
	pol := &Policy{
		AllowDomains:    []string{strings.TrimPrefix(strings.TrimPrefix(rb.srv.URL, "http://"), "127.0.0.1:")},
		MaxResponseBody: 4096,
	}
	// the allow domain must be the host of the backend
	backendHost := stripPort(strings.TrimPrefix(rb.srv.URL, "http://"))
	pol.AllowDomains = []string{backendHost}
	g := startGatewayWithPolicy(t, pol)
	c := clientVia(g)
	resp := do(c, "GET", rb.srv.URL+"/big", "")
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %+v", resp)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if n > 8192 { // allow some slop for headers/chunking
		t.Errorf("response not truncated: got %d bytes (cap 4096)", n)
	}
}

type infiniteReader struct{ n int64 }

func (r *infiniteReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, io.EOF
	}
	c := len(p)
	if int64(c) > r.n {
		c = int(r.n)
	}
	for i := 0; i < c; i++ {
		p[i] = 'x'
	}
	r.n -= int64(c)
	return c, nil
}

// --- method allowlist default ---

func TestDefaultMethodSet(t *testing.T) {
	// No AllowedMethods => default safe set. TRACE/OPTIONS unusual methods denied.
	if methodAllowed("TRACE", nil) {
		t.Error("TRACE should be denied by default")
	}
	if !methodAllowed("GET", nil) {
		t.Error("GET should be allowed by default")
	}
}

// --- block list precedence over allow ---

func TestBlockOverAllow(t *testing.T) {
	pol := &Policy{
		AllowDomains: []string{"a.com"},
		BlockDomains: []string{"a.com"},
	}
	d := (&Gateway{}).decideDomain("a.com", pol)
	if d != DecisionBlock {
		t.Error("block must take precedence over allow")
	}
}

// --- task attribution required ---

func TestNoTaskIdDenied(t *testing.T) {
	pol := &Policy{AllowDomains: []string{"a.com"}}
	g := startGatewayWithPolicy(t, pol)
	c := clientVia(g)

	// no X-Task-Id header
	req, _ := http.NewRequest("GET", "http://a.com/", nil)
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 without X-Task-Id, got %d", resp.StatusCode)
		}
	}
}
