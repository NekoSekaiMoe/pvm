package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
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

// TestConnectTunnelOpaque_NoInject pins the documented limitation of
// EgressInject on CONNECT: a rule with Inject may authorize an HTTPS tunnel
// (host-level match), but the tunnel relays opaque TLS bytes, so the target
// must receive EXACTLY what the client wrote — no credential header can be
// (or ever was) attached. This exercises the real handle dispatch
// (handle -> handleConnect -> pipe), not a direct ApplyInject call.
func TestConnectTunnelOpaque_NoInject(t *testing.T) {
	// A raw TCP target that records the first bytes it receives.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	target := ln.Addr().String()

	payload := []byte("OPAQUE-TUNNEL-PAYLOAD\r\n")
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		buf := make([]byte, len(payload))
		_, _ = io.ReadFull(conn, buf)
		got <- buf
		conn.Close()
	}()

	// A rule that would inject on any plain-HTTPS request it matches.
	allow := true
	pol := &Policy{Rules: []EgressRule{{
		Host:   "127.0.0.1", // matches the CONNECT target (host:port)
		Allow:  &allow,
		Inject: &EgressInject{Header: "Authorization", Secret: "top-secret-token"},
	}}}
	g := startGateway(t, pol)

	// Drive the CONNECT through the gateway's real HTTP dispatch.
	conn, err := net.DialTimeout("tcp", g.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Task-Id: t1\r\n\r\n", target, target)

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		rest, _ := io.ReadAll(br)
		t.Fatalf("CONNECT status = %q body = %q (err %v), want 200", status, rest, err)
	}
	for { // drain the response headers
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read response headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	select {
	case b := <-got:
		if string(b) != string(payload) {
			t.Fatalf("tunnel payload mutated: target got %q, want %q (no injection is possible through an opaque tunnel)", b, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("target received nothing through the tunnel")
	}
}
