package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"uml-container/internal/audit"
)

// Echo backend that records the request so tests can assert what reached it.
// The mutex makes reqs safe to read from the test goroutine while the
// backend handler appends concurrently.
type recordingBackend struct {
	mu   sync.Mutex
	reqs []string
	srv  *httptest.Server
}

func newRecordingBackend(t *testing.T) *recordingBackend {
	rb := &recordingBackend{}
	rb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rb.record(r.Method + " " + r.URL.Path)
		io.WriteString(w, "ok")
	}))
	t.Cleanup(rb.srv.Close)
	return rb
}

func (rb *recordingBackend) record(req string) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.reqs = append(rb.reqs, req)
}

func (rb *recordingBackend) recorded() []string {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return append([]string(nil), rb.reqs...)
}

func startGatewayWithPolicy(t *testing.T, pol *Policy) *Gateway {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("egress-edge")
	g := NewGateway()
	g.EnableSSRFBypassForTest() // tests route to httptest backends on 127.0.0.1
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
		{"github.com", "*.github.com", false},    // wildcard needs a subdomain
		{"apigithub.com", "*.github.com", false}, // suffix must be dot-prefixed
		{"evil.com", "*.github.com", false},
		{"a.b.github.com", "*.github.com", true}, // multi-level sub
		{"github.com", "github.com", true},
		{"GITHUB.COM", "github.com", true},                 // case handled at the decide layer
		{"api.github.com.evil.com", "*.github.com", false}, // suffix hijack
	}
	for _, c := range cases {
		// Drive the host through viewFromHTTP + decideDomain so mixed-case
		// inputs exercise the decision layer's own lowercasing. Pre-lowering
		// the host here (the old domainMatches-only form) would mask a
		// decision-layer case-handling regression.
		v := viewFromHTTP(mustReq(t, "GET", "http://"+c.host+"/x"))
		pol := &Policy{AllowDomains: []string{c.rule}}
		got := (&Gateway{}).decideDomain(v, pol) == DecisionAllow
		if got != c.want {
			t.Errorf("decideDomain(host=%q, allow=%q) allowed = %v, want %v", c.host, c.rule, got, c.want)
		}
	}
}

// --- forwarded path must match the policy view ---

// TestForwardedPathNormalized verifies handleHTTP forwards the SAME
// normalized path the policy evaluated (viewFromHTTP/normalizePath): a
// request whose raw path is "//a/../b" is both judged — and forwarded — as
// "/b". Without the fix, the policy matched "/b" while the upstream
// received the raw "//a/../b".
func TestForwardedPathNormalized(t *testing.T) {
	rb := newRecordingBackend(t)
	backendHost := stripPort(strings.TrimPrefix(rb.srv.URL, "http://"))
	allow := true
	pol := &Policy{Rules: []EgressRule{
		{Name: "b-only", Host: backendHost, Path: "/b", Allow: &allow},
	}}
	g := startGatewayWithPolicy(t, pol)
	c := clientVia(g)

	// "//a/../b" cleans to "/b": the rule matches ONLY the cleaned path, and
	// the upstream must receive the cleaned path too.
	resp := do(c, "GET", rb.srv.URL+"//a/../b", "")
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %+v", resp)
	}
	resp.Body.Close()
	reqs := rb.recorded()
	if len(reqs) == 0 {
		t.Fatal("no request reached backend")
	}
	if got := reqs[0]; got != "GET /b" {
		t.Fatalf("upstream received %q, want %q (policy-normalized path)", got, "GET /b")
	}
}

// --- SSRF floor: proxy must refuse to CONNECT to a private IP even if the
// domain itself is allowlisted (defense against DNS rebinding). ---

// TestSSRF_PrivateIPBlocked verifies the handleHTTP SSRF floor: even when a
// domain is allowlisted, a dial that resolves to a loopback/private IP must be
// refused with 403. Unlike the old variant, this points at a REAL httptest
// upstream on 127.0.0.1 — if the floor is missing, the proxy forwards and we
// get 200, failing the test. (securitytest.TestAttack_DNSRebindingToPrivateIP
// covers the same property end-to-end.)
func TestSSRF_PrivateIPBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pol := &Policy{AllowDomains: []string{"127.0.0.1"}}
	// Build the gateway WITHOUT EnableSSRFBypassForTest so the floor is active.
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("ssrf-floor")
	g := NewGateway()
	g.SetPolicy("ssrf", pol)
	g.AttachLedger(l)
	if _, err := g.Listen(nil, "127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { g.Shutdown(nil) })
	c := clientVia(g)

	req, _ := http.NewRequest("GET", upstream.URL+"/nope", nil)
	req.Header.Set("X-Task-Id", "ssrf")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 from SSRF floor, got %d", resp.StatusCode)
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
	v := viewFromHTTP(mustReq(t, "GET", "http://a.com/"))
	d := (&Gateway{}).decideDomain(v, pol)
	if d != DecisionBlock {
		t.Error("block must take precedence over allow")
	}
}

func mustReq(t *testing.T, method, rawurl string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawurl, nil)
	if err != nil {
		t.Fatalf("bad test request %q: %v", rawurl, err)
	}
	return req
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
