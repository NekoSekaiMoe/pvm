package egress

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestLoadOrCreateCAIdempotent(t *testing.T) {
	dir := t.TempDir()
	ca1, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca1.leaf.Raw) != string(ca2.leaf.Raw) {
		t.Fatal("CA must be stable across loads")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal("ca.key must persist")
	}
	// Corrupt key must NOT be silently regenerated.
	os.WriteFile(filepath.Join(dir, "ca.key"), []byte("garbage"), 0o600)
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("corrupt CA must fail, not regenerate")
	}
}

// TestMITMInjectEndToEnd drives the full interception path: a client that
// trusts the pvm egress CA sends CONNECT + a real request; the gateway
// terminates TLS, injects the credential, and forwards over TLS to the
// upstream, which asserts the header arrived.
func TestMITMInjectEndToEnd(t *testing.T) {
	// Upstream: real TLS server recording the Authorization header.
	var gotAuth string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "upstream-ok")
	}))
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	upHost := upURL.Host // 127.0.0.1:port

	// Gateway with an MITM inject rule for the upstream host.
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway()
	g.EnableSSRFBypassForTest() // upstream is loopback (test-only floor lift)
	g.EnableMITM(ca)
	// The httptest upstream presents a self-signed cert; production
	// gateways verify upstreams against system roots — here (in-package
	// test) swap the shared transport for a trusting one.
	g.transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	secret := "topsecret"
	upPort := mustAtoi(upURL.Port())
	g.SetPolicy("t-mitm", &Policy{
		Rules: []EgressRule{{
			Name:   "inject-api",
			Host:   strings.Split(upHost, ":")[0],
			SNI:    strings.Split(upHost, ":")[0],
			Port:   upPort,
			Allow:  boolPtr(true),
			Inject: &EgressInject{Header: "Authorization", Format: "Bearer ${SECRET}", Secret: secret},
			MITM:   boolPtr(true),
		}},
	})
	tl, err := g.ListenForTaskOn(nil, "t-mitm", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tl.Addr()
	defer tl.Close()

	// Client: CONNECT through the proxy, trusting ONLY the pvm CA for the
	// inner TLS (the upstream's self-signed cert is reached by the gateway).
	proxyConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyConn.Close()
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upHost, upHost)
	br := bufio.NewReader(proxyConn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %q %v", status, err)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}

	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(filepath.Join(ca.dir, "ca.crt"))
	pool.AppendCertsFromPEM(caPEM)
	tlsConn := tls.Client(proxyConn, &tls.Config{
		ServerName: strings.Split(upHost, ":")[0],
		RootCAs:    pool,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("inner handshake (client must trust egress CA): %v", err)
	}

	// The inner request rides the SAME TLS connection (no fresh dial —
	// that would bypass the tunnel).
	req, _ := http.NewRequest(http.MethodGet, "https://"+upHost+"/v1/data", nil)
	req.Header.Set("X-Task-Id", "t-mitm")
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("inner write: %v", err)
	}
	inner := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(inner, req)
	if err != nil {
		t.Fatalf("inner response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inner status = %d", resp.StatusCode)
	}
	if gotAuth != "Bearer "+secret {
		t.Fatalf("upstream Authorization = %q, want injected Bearer secret", gotAuth)
	}
}

// TestPlainHTTPInjectOptIn pins the two plaintext behaviors: default refuse,
// AllowPlainHTTP attach.
func TestPlainHTTPInjectOptIn(t *testing.T) {
	g := NewGateway()
	pol := &Policy{Rules: []EgressRule{
		{Name: "plain", Host: "api.internal", Inject: &EgressInject{Header: "X-Secret", Secret: "s1", AllowPlainHTTP: true}},
		{Name: "strict", Host: "safe.internal", Inject: &EgressInject{Header: "X-Secret", Secret: "s2"}},
	}}
	g.SetPolicy("t", pol)

	req, _ := http.NewRequest(http.MethodGet, "http://api.internal/x", nil)
	v := viewFromHTTP(req)
	g.ApplyInject(req, v, pol)
	if req.Header.Get("X-Secret") != "s1" {
		t.Fatal("AllowPlainHTTP rule must inject on plaintext")
	}

	req2, _ := http.NewRequest(http.MethodGet, "http://safe.internal/x", nil)
	v2 := viewFromHTTP(req2)
	g.ApplyInject(req2, v2, pol)
	if req2.Header.Get("X-Secret") != "" {
		t.Fatal("default rule must NOT inject on plaintext")
	}
}

func mustAtoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
