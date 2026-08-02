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

func tmpLedger(t *testing.T) *audit.Ledger {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, err := audit.Open("egress-test")
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	return l
}

// startGateway boots a gateway on an ephemeral port and returns it plus the
// URL clients should use as their proxy.
func startGateway(t *testing.T, pol *Policy) *Gateway {
	t.Helper()
	g := NewGateway()
	g.EnableSSRFBypassForTest() // tests route to httptest backends on 127.0.0.1
	g.SetPolicy("t1", pol)
	g.AttachLedger(tmpLedger(t))
	addr, err := g.Listen(nil, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { g.Shutdown(nil) })
	_ = addr
	return g
}

// A backend that just echoes "ok".
func echoBackend(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDomainAllow(t *testing.T) {
	// We can't easily resolve a real domain in CI; use the loopback backend's
	// Host header to exercise the allow path. Policies use the backend's host.
	be := echoBackend(t)
	hostport := strings.TrimPrefix(be.URL, "http://")
	host := stripPort(hostport)
	pol := &Policy{AllowDomains: []string{host}}
	g := startGateway(t, pol)

	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://" + g.Addr())
		},
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("GET", be.URL, nil)
	req.Header.Set("X-Task-Id", "t1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestDomainBlock(t *testing.T) {
	be := echoBackend(t)
	host := stripPort(strings.TrimPrefix(be.URL, "http://"))
	pol := &Policy{
		AllowDomains: []string{host},
		BlockDomains: []string{host}, // block wins
	}
	g := startGateway(t, pol)

	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("GET", be.URL, nil)
	req.Header.Set("X-Task-Id", "t1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 block, got status %d", resp.StatusCode)
	}
}

func TestWildcardMatch(t *testing.T) {
	if !domainMatches("api.github.com", "*.github.com") {
		t.Error("*.github.com should match api.github.com")
	}
	if domainMatches("evil.com", "*.github.com") {
		t.Error("*.github.com should NOT match evil.com")
	}
	if !domainMatches("github.com", "github.com") {
		t.Error("exact match failed")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	be := echoBackend(t)
	host := stripPort(strings.TrimPrefix(be.URL, "http://"))
	pol := &Policy{AllowDomains: []string{host}, AllowedMethods: []string{"GET"}}
	g := startGateway(t, pol)

	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("DELETE", be.URL, nil)
	req.Header.Set("X-Task-Id", "t1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestRequestBodyTooLarge(t *testing.T) {
	be := echoBackend(t)
	host := stripPort(strings.TrimPrefix(be.URL, "http://"))
	pol := &Policy{AllowDomains: []string{host}, MaxRequestBody: 4}
	g := startGateway(t, pol)

	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("POST", be.URL, strings.NewReader("this is way too long"))
	req.Header.Set("X-Task-Id", "t1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", resp.StatusCode)
	}
}

func TestNoPolicy_DefaultDeny(t *testing.T) {
	g := NewGateway()
	g.AttachLedger(tmpLedger(t))
	_, err := g.Listen(nil, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { g.Shutdown(nil) })

	// request with task that has NO policy registered
	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Task-Id", "unknown-task")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 default-deny, got %d", resp.StatusCode)
	}
}

func TestBytesAccounting(t *testing.T) {
	be := echoBackend(t)
	host := stripPort(strings.TrimPrefix(be.URL, "http://"))
	pol := &Policy{AllowDomains: []string{host}}
	g := startGateway(t, pol)

	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", be.URL, nil)
	req.Header.Set("X-Task-Id", "t1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if g.BytesUsed("t1") == 0 {
		t.Error("expected non-zero bytes accounted")
	}
}
