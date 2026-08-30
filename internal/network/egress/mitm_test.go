package egress

// mitm_test.go drives the real CONNECT → TLS-termination → re-encrypt
// pipeline end to end: a raw TCP client CONNECTs through the gateway, the
// gateway terminates the inner TLS with the egress CA, and the plaintext
// request is re-encrypted to an httptest TLS upstream. The tests pin the
// review regressions: blocked tunnels must be audited (BytesDenied), the
// task-wide method allowlist and body caps must bind inside the tunnel,
// and the policy view must follow the CONNECT destination — never the
// forgeable inner Host header.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mitmTestEnv wires a gateway, its egress CA and a TLS upstream together.
// The CONNECT target is the upstream's 127.0.0.1 host:port, so the whole
// interception path (leaf minting, SNI, upstream re-encrypt) is exercised.
type mitmTestEnv struct {
	g        *Gateway
	ca       *CA
	upstream *httptest.Server
	hits     *int64
}

func newMITMEnv(t *testing.T, pol *Policy, upstreamBody string) *mitmTestEnv {
	t.Helper()
	var hits int64
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if v := r.Header.Get("X-Inject"); v != "" {
			// Echo the injected credential header so tests can observe it.
			w.Header().Set("X-Saw-Inject", v)
		}
		io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(up.Close)

	g := NewGateway()
	g.EnableSSRFBypassForTest() // loopback upstream
	g.SetPolicy("t1", pol)
	g.AttachLedger(tmpLedger(t))
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("mitm ca: %v", err)
	}
	g.EnableMITM(ca)
	// The upstream is httptest's self-signed TLS server; swap the shared
	// transport for one that skips verification. Test-only, same spirit as
	// EnableSSRFBypassForTest — production keeps the verifying default.
	g.mu.Lock()
	g.transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	g.mu.Unlock()
	if _, err := g.Listen(nil, "127.0.0.1:0"); err != nil {
		t.Fatalf("gateway listen: %v", err)
	}
	t.Cleanup(func() { _ = g.Shutdown(nil) })
	return &mitmTestEnv{g: g, ca: ca, upstream: up, hits: &hits}
}

// target returns the CONNECT target (the upstream's host:port).
func (e *mitmTestEnv) target() string { return strings.TrimPrefix(e.upstream.URL, "https://") }

// mitmTunnel opens a CONNECT tunnel through the gateway and completes the
// TLS handshake against the MITM CA, returning the plaintext stream.
func mitmTunnel(t *testing.T, env *mitmTestEnv) net.Conn {
	t.Helper()
	target := env.target()
	conn, err := net.Dial("tcp", env.g.Addr())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Task-Id: t1\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	// Bytes the client pipelined past the 200 must not be lost to the
	// response reader (mirror of serveMITM's own drain).
	src := net.Conn(conn)
	if n := br.Buffered(); n > 0 {
		src = &prefixedConn{Conn: conn, r: io.MultiReader(io.LimitReader(br, int64(n)), conn)}
	}
	pool := x509.NewCertPool()
	pool.AddCert(env.ca.leaf)
	tlsConn := tls.Client(src, &tls.Config{
		ServerName: stripPortMITM(target),
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("tls handshake with mitm leaf: %v", err)
	}
	return tlsConn
}

// mitmRoundTrip sends one plaintext HTTP/1.1 request through the tunnel
// and reads the response. hostHeader overrides the inner Host header to
// exercise forged-Host handling (it never changes where traffic goes: the
// gateway always forwards to the CONNECT destination).
func mitmRoundTrip(t *testing.T, c net.Conn, method, path, hostHeader, body string) *http.Response {
	t.Helper()
	if hostHeader == "" {
		hostHeader = "upstream.invalid"
	}
	raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
		method, path, hostHeader, len(body), body)
	if _, err := c.Write([]byte(raw)); err != nil {
		t.Fatalf("write inner request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read inner response: %v", err)
	}
	return resp
}

// mitmAllowRule builds the minimal MITM rule for host: allow + intercept +
// inject, no path/method constraints (so the CONNECT view matches too).
func mitmAllowRule(host string) EgressRule {
	yes := true
	return EgressRule{
		Name:   "mitm-" + host,
		Host:   host,
		Allow:  &yes,
		MITM:   &yes,
		Inject: &EgressInject{Header: "X-Inject", Secret: "sekret"},
	}
}

// TestMITM_AllowedPipelineInjects pins the happy path: an allowed tunnel
// proxies the request, injects the rule's credential upstream, and returns
// the upstream body to the client.
func TestMITM_AllowedPipelineInjects(t *testing.T) {
	env := newMITMEnv(t, &Policy{Rules: []EgressRule{mitmAllowRule("127.0.0.1")}}, "hello")
	c := mitmTunnel(t, env)
	defer c.Close()

	resp := mitmRoundTrip(t, c, http.MethodGet, "/x", env.target(), "")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want %q", body, "hello")
	}
	if got := atomic.LoadInt64(env.hits); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	if got := resp.Header.Get("X-Saw-Inject"); got != "sekret" {
		t.Fatalf("injected credential not observed upstream: %q", got)
	}
}

// TestMITM_BlockIsAudited: a decision-blocked inner request must be
// recorded (BytesDenied + ledger), not silently 403'd.
func TestMITM_BlockIsAudited(t *testing.T) {
	no := false
	pol := &Policy{Rules: []EgressRule{
		// First-match-wins: /secret/* is denied, everything else on the
		// CONNECT host goes through the MITM rule.
		{Name: "deny-secret", Host: "127.0.0.1", Path: "/secret/*", Allow: &no},
		mitmAllowRule("127.0.0.1"),
	}}
	env := newMITMEnv(t, pol, "hello")
	c := mitmTunnel(t, env)
	defer c.Close()

	before := env.g.BytesDenied("t1")
	resp := mitmRoundTrip(t, c, http.MethodGet, "/secret/x", env.target(), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if after := env.g.BytesDenied("t1"); after != before+1 {
		t.Fatalf("BytesDenied = %d, want %d (block must be audited)", after, before+1)
	}
	if got := atomic.LoadInt64(env.hits); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}
}

// TestMITM_MethodAllowlistBindsInsideTunnel: the task-wide method
// allowlist must apply to intercepted requests — a MITM rule must not
// widen it.
func TestMITM_MethodAllowlistBindsInsideTunnel(t *testing.T) {
	env := newMITMEnv(t, &Policy{
		AllowedMethods: []string{http.MethodGet},
		Rules:          []EgressRule{mitmAllowRule("127.0.0.1")},
	}, "hello")
	c := mitmTunnel(t, env)
	defer c.Close()

	before := env.g.BytesDenied("t1")
	resp := mitmRoundTrip(t, c, http.MethodDelete, "/x", env.target(), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	if after := env.g.BytesDenied("t1"); after != before+1 {
		t.Fatalf("BytesDenied = %d, want %d", after, before+1)
	}
	if got := atomic.LoadInt64(env.hits); got != 0 {
		t.Fatalf("upstream hits = %d, want 0 (no upstream connection on deny)", got)
	}
}

// TestMITM_RequestBodyCapBindsInsideTunnel: a declared request body over
// the task cap is rejected before any upstream connection.
func TestMITM_RequestBodyCapBindsInsideTunnel(t *testing.T) {
	env := newMITMEnv(t, &Policy{
		MaxRequestBody: 10,
		Rules:          []EgressRule{mitmAllowRule("127.0.0.1")},
	}, "hello")
	c := mitmTunnel(t, env)
	defer c.Close()

	resp := mitmRoundTrip(t, c, http.MethodPost, "/x", env.target(), strings.Repeat("a", 20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if got := atomic.LoadInt64(env.hits); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}
}

// TestMITM_ResponseBodyCapTruncates: responses over the task cap are
// truncated to the cap (same semantics as the plaintext path).
func TestMITM_ResponseBodyCapTruncates(t *testing.T) {
	env := newMITMEnv(t, &Policy{
		MaxResponseBody: 8,
		Rules:           []EgressRule{mitmAllowRule("127.0.0.1")},
	}, "0123456789abcdef")
	c := mitmTunnel(t, env)
	defer c.Close()

	resp := mitmRoundTrip(t, c, http.MethodGet, "/x", env.target(), "")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(body) > 8 {
		t.Fatalf("body len = %d, want <= 8 (cap not enforced)", len(body))
	}
}

// TestMITM_HostHeaderIsNotTrusted: the policy must evaluate the CONNECT
// destination, not the (forgeable) inner Host header. The client CONNECTs
// to the intercepted host — where /admin is denied — but claims
// Host: good.test, whose rule allows everything. Before the fix the policy
// evaluated good.test, allowed the request, and forwarded it to the
// /admin-denied destination anyway.
func TestMITM_HostHeaderIsNotTrusted(t *testing.T) {
	no, yes := false, true
	pol := &Policy{Rules: []EgressRule{
		{Name: "deny-admin", Host: "127.0.0.1", Path: "/admin", Allow: &no},
		{Name: "mitm", Host: "127.0.0.1", Allow: &yes, MITM: &yes, Inject: &EgressInject{Header: "X-Inject", Secret: "s"}},
		{Name: "forged-name", Host: "good.test", Allow: &yes},
	}}
	env := newMITMEnv(t, pol, "hello")
	c := mitmTunnel(t, env)
	defer c.Close()

	resp := mitmRoundTrip(t, c, http.MethodDelete, "/admin", "good.test", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged-Host request status = %d, want 403 (policy must follow the CONNECT destination)", resp.StatusCode)
	}
	if got := atomic.LoadInt64(env.hits); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}

	// Sanity: the same request with the honest Host is denied identically.
	resp = mitmRoundTrip(t, c, http.MethodDelete, "/admin", env.target(), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("honest-Host /admin status = %d, want 403", resp.StatusCode)
	}
}

// TestMITM_RejectedRequestKeepsTunnelFramed: a rejected inner request must
// have its body drained (or the tunnel closed) before the next request is
// read — otherwise http.ReadRequest parses the leftover body bytes as a new
// request line and the keep-alive tunnel desyncs.
func TestMITM_RejectedRequestKeepsTunnelFramed(t *testing.T) {
	env := newMITMEnv(t, &Policy{
		AllowedMethods: []string{http.MethodGet},
		Rules:          []EgressRule{mitmAllowRule("127.0.0.1")},
	}, "hello")
	c := mitmTunnel(t, env)
	defer c.Close()

	// 1) POST is outside the allowlist: rejected while a body is attached.
	resp := mitmRoundTrip(t, c, http.MethodPost, "/submit", "", "LEFTOVER-BODY-BYTES")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("rejected request status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	// 2) A second request on the SAME keep-alive tunnel must still parse
	// and proxy: this is exactly what breaks without the drain.
	resp2 := mitmRoundTrip(t, c, http.MethodGet, "/ok", "", "")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("follow-up request status = %d, want 200 (tunnel desynced)", resp2.StatusCode)
	}
	b, _ := io.ReadAll(resp2.Body)
	if string(b) != "hello" {
		t.Fatalf("follow-up body = %q, want %q", b, "hello")
	}
}
