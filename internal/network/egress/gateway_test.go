package egress

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

// TestBytesAccounting_UpstreamErrorBillsForwardedBody pins the billing on
// handleHTTP's upstream-error branch: when the upstream dies mid-request,
// the request-body bytes the countingReader already read (and forwarded)
// must land in BytesUsed — without an addBytes on that branch a partially
// transmitted body would egress for free.
func TestBytesAccounting_UpstreamErrorBillsForwardedBody(t *testing.T) {
	const bodySize = 32 // bytes the client POSTs through the gateway
	// Backend from hell: hijacks the connection, consumes the request head
	// plus a slice of the (chunked) forwarded body, then slams the socket
	// without ever answering. RoundTrip fails mid-transfer, so only the
	// upstream-error branch can do the accounting.
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("backend does not support hijack")
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		// Bound the read so a broken gateway cannot wedge this handler
		// (and the t.Cleanup be.Close below) forever.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		// The server has already consumed the request head, so the bufio
		// is positioned on the chunked-body framing. Consume only part of
		// the first chunk on the wire (its size line plus a slice of the
		// data) before killing the connection mid-transfer.
		if _, err := io.ReadFull(brw.Reader, make([]byte, 16)); err != nil {
			return
		}
		conn.Close()
	}))
	t.Cleanup(be.Close)
	host := stripPort(strings.TrimPrefix(be.URL, "http://"))
	pol := &Policy{AllowDomains: []string{host}}
	g := startGateway(t, pol)

	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	body := strings.Repeat("B", bodySize)
	req, _ := http.NewRequest("POST", be.URL, strings.NewReader(body))
	req.Header.Set("X-Task-Id", "t1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d (upstream-error branch)", resp.StatusCode, http.StatusBadGateway)
	}
	// The error branch bills BEFORE writing the 502, so once the client
	// observes the response the counter has settled. The transport drains
	// the whole small body through the countingReader in one pass before
	// the upstream kills the connection, so exactly bodySize bytes were
	// forwarded — and must be accounted, never zero.
	if got := g.BytesUsed("t1"); got != int64(bodySize) {
		t.Fatalf("BytesUsed = %d, want %d (body forwarded to a failing upstream must still count)", got, bodySize)
	}
}

// TestBytesAccounting_ConnectTunnelUploadOnly pins that the CONNECT tunnel
// bills exactly the client→upstream copy: bytes the target sends back
// (download direction, here a different size) must not count.
func TestBytesAccounting_ConnectTunnelUploadOnly(t *testing.T) {
	const (
		upload   = "EGRESS-PAYLOAD"        // 14 bytes client → target
		download = "DOWNSTREAM-RESPONSE!!" // 21 bytes target → client
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

	// Write IMMEDIATELY after the 200: handleConnect now completes the
	// hijack before answering, so the client's first tunnel byte can no
	// longer race (and lose itself to) the server's background read.
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

	// Write IMMEDIATELY: handleConnect completes the hijack before sending
	// the 200, so the full payload must arrive intact with no delay — this
	// also regression-tests that the handoff race is gone.
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

func TestSetPolicyInvalidatesLiveTunnels(t *testing.T) {
	g := NewGateway()
	c1, c2 := net.Pipe()
	defer c2.Close()
	g.trackTunnel("tk", c1)

	if gen := g.PolicyGeneration("tk"); gen != 0 {
		t.Fatalf("fresh task generation = %d, want 0", gen)
	}
	g.SetPolicy("tk", &Policy{AllowDomains: []string{"a.example"}})
	if gen := g.PolicyGeneration("tk"); gen != 1 {
		t.Fatalf("generation after update = %d, want 1", gen)
	}
	// The tracked tunnel must now be closed: a read on the OTHER end
	// returns io.EOF. Requiring the real EOF (not any error) matters:
	// an untracked tunnel would only fail via the read deadline above,
	// and accepting that would let the test pass without any close.
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c2.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("tracked tunnel must be closed with io.EOF, got %v", err)
	}
	// The registry entry is gone: a second update closes nothing and the
	// generation still bumps.
	g.SetPolicy("tk", &Policy{})
	if gen := g.PolicyGeneration("tk"); gen != 2 {
		t.Fatalf("generation after second update = %d, want 2", gen)
	}
	_ = c1.Close()
}

// Regression for the CONNECT/transparent-splice TOCTOU: a tunnel whose
// verdict was computed against generation N must not register after
// SetPolicy already bumped to N+1 and swept the registered tunnels.
func TestTrackTunnelIfFreshRejectsStaleGeneration(t *testing.T) {
	g := NewGateway()
	g.SetPolicy("tk", &Policy{AllowDomains: []string{"a.example"}})
	staleGen := g.PolicyGeneration("tk") // verdict computed here

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Policy moves AFTER the verdict: the sweep closes registered tunnels.
	g.SetPolicy("tk", &Policy{})
	if g.trackTunnelIfFresh("tk", staleGen, c1) {
		t.Fatal("stale-generation registration must be refused")
	}
	// The refused conn was NOT registered: nothing closes it later.
	g.SetPolicy("tk", &Policy{})
	c2.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := c2.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("refused tunnel must stay open (caller closes it), got %v", err)
	}

	// A fresh generation registers and IS swept by the next update.
	fresh := g.PolicyGeneration("tk")
	if !g.trackTunnelIfFresh("tk", fresh, c1) {
		t.Fatal("fresh-generation registration must succeed")
	}
	g.SetPolicy("tk", &Policy{})
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("fresh-registered tunnel must be closed by SetPolicy, got %v", err)
	}
}
