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

// TestBytesAccounting_HTTPRequestBodyOnly pins that the HTTP proxy mode
// bills ONLY the sandbox→upstream direction: a POST's request body counts
// against BytesUsed, the (much larger) response body does not.
func TestBytesAccounting_HTTPRequestBodyOnly(t *testing.T) {
	// Backend drains the request and answers with a body far LARGER than
	// the request — if response bytes leaked into the accounting, the exact
	// equality below fails loudly.
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, strings.Repeat("R", 512))
	}))
	t.Cleanup(be.Close)
	host := stripPort(strings.TrimPrefix(be.URL, "http://"))
	pol := &Policy{AllowDomains: []string{host}}
	g := startGateway(t, pol)

	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	body := strings.Repeat("B", 16)
	req, _ := http.NewRequest("POST", be.URL, strings.NewReader(body))
	req.Header.Set("X-Task-Id", "t1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// The handler's addBytes runs right after it finishes writing the
	// response — which the client may observe first. Poll briefly for the
	// exact request-body size instead of asserting immediately.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := g.BytesUsed("t1"); got == int64(len(body)) {
			break
		} else if got > int64(len(body)) {
			t.Fatalf("BytesUsed = %d, want %d (response bytes must not count)", got, len(body))
		}
		if time.Now().After(deadline) {
			t.Fatalf("BytesUsed = %d, want %d (request body only; response bytes must not count)", g.BytesUsed("t1"), len(body))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestBytesAccounting_ConnectTunnelUploadOnly pins that the CONNECT tunnel
// bills exactly the client→upstream copy: bytes the target sends back
// (download direction, here a different size) must not count.
func TestBytesAccounting_ConnectTunnelUploadOnly(t *testing.T) {
	const (
		upload   = "EGRESS-PAYLOAD"        // 14 bytes client → target
		download = "DOWNSTREAM-RESPONSE!!" // 20 bytes target → client
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	target := ln.Addr().String()

	replySeen := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len(upload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		// Reply with a DIFFERENT-size payload so a download-billing
		// regression cannot pass the exact-value assertion below.
		conn.Write([]byte(download))
		close(replySeen)
	}()

	// Extended-rules policy (flat mode restricts CONNECT to ports 80/443;
	// the test target is on an ephemeral port).
	allow := true
	pol := &Policy{Rules: []EgressRule{{Host: "127.0.0.1", Allow: &allow}}}
	g := startGateway(t, pol)

	conn, err := net.DialTimeout("tcp", g.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Task-Id: t1\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	if status, err := br.ReadString('\n'); err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q (err %v), want 200", status, err)
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

	// Give the gateway's hijack time to fully release the server-side
	// background read: net/http flushes the 200 response BEFORE aborting
	// that read, so a client write racing the abort can lose its first byte
	// to the read's 1-byte buffer (a pre-existing tunnel race — see
	// TestConnectTunnelOpaque_NoInject, which flakes on it). Delaying here
	// keeps this accounting test deterministic.
	time.Sleep(100 * time.Millisecond)

	if _, err := conn.Write([]byte(upload)); err != nil {
		t.Fatalf("write upload: %v", err)
	}
	got := make([]byte, len(download))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read tunnel reply: %v", err)
	}
	select {
	case <-replySeen:
	case <-time.After(2 * time.Second):
		t.Fatal("target never saw the upload")
	}

	// The billed pipe settles asynchronously once the tunnel winds down;
	// poll briefly for the exact upload size.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if g.BytesUsed("t1") == int64(len(upload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("BytesUsed = %d, want %d (upload only; download is %d bytes and must not count)",
				g.BytesUsed("t1"), len(upload), len(download))
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Give a (wrongly billed) download pipe a moment to land and re-assert
	// the total has not grown past the upload size.
	time.Sleep(50 * time.Millisecond)
	if got := g.BytesUsed("t1"); got != int64(len(upload)) {
		t.Fatalf("BytesUsed grew to %d after tunnel settled, want %d (upload only)", got, len(upload))
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

	// Delay past the hijack window: net/http flushes the CONNECT 200 BEFORE
	// aborting its 1-byte background read, so a payload written immediately
	// can lose its first byte to that read (pre-existing race, not the
	// property under test). Sleeping keeps this test deterministic.
	time.Sleep(100 * time.Millisecond)

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
