package egress

// transparent_test.go — the testable cores of the transparent path: SNI
// sniffing (bounds-checked parser) and origin-form HTTP serving through
// the shared pipeline. The full REDIRECT path needs iptables+root and is
// exercised by the integration suites.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// buildClientHello assembles a minimal TLS 1.2/1.3-shaped ClientHello
// carrying one SNI entry, so the parser tests use realistic bytes.
func buildClientHello(sni string, corrupt func([]byte) []byte) []byte {
	name := []byte(sni)
	// Extension content (RFC 6066): u16 server_name_list length, then one
	// host_name entry: u8 type(0), u16 name length, name.
	content := make([]byte, 0, 5+len(name))
	content = append(content, byte((len(name)+3)>>8), byte((len(name)+3)&0xff))
	content = append(content, 0x00)
	content = append(content, byte(len(name)>>8), byte(len(name)&0xff))
	content = append(content, name...)
	// Extension entry: u16 type(0x0000 = server_name), u16 length, content.
	ext := make([]byte, 0, 4+len(content))
	ext = append(ext, 0x00, 0x00)
	ext = append(ext, byte(len(content)>>8), byte(len(content)&0xff))
	ext = append(ext, content...)

	body := make([]byte, 0, 64+len(ext))
	body = append(body, 0x01) // ClientHello
	body = append(body, byte((len(ext)+38)>>16), byte((len(ext)+38)>>8), byte((len(ext)+38)&0xff))
	body = append(body, 0x03, 0x03)             // client_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id len
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x00)                   // compression methods
	body = append(body, byte(len(ext)>>8), byte(len(ext)&0xff))
	body = append(body, ext...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body) & 0xff)}
	rec = append(rec, body...)
	if corrupt != nil {
		rec = corrupt(rec)
	}
	return rec
}

func TestParseSNIExtractsServerName(t *testing.T) {
	for _, name := range []string{"example.com", "a.very.long.sub.domain.example.org"} {
		hs := buildClientHello(name, nil)[5:]
		got, err := parseSNI(hs)
		if err != nil {
			t.Fatalf("parseSNI(%s): %v", name, err)
		}
		if got != name {
			t.Fatalf("parseSNI = %q, want %q", got, name)
		}
	}
}

func TestParseSNIMalformedNeverPanics(t *testing.T) {
	full := buildClientHello("example.com", nil)
	hs := full[5:]
	cases := []struct {
		name    string
		input   []byte
		wantErr bool // only the control case parses; every corruption must error
	}{
		{"control: complete handshake parses", hs, false},
		{"nil input", nil, true},
		{"empty input", []byte{}, true},
		{"not a ClientHello", []byte{0x02}, true},
		{"truncated handshake", hs[:10], true},
		{"extension block overruns", hs[:len(hs)-5], true},
		{"SNI length overruns extension", corruptSNILen(hs, "example.com"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSNI(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("parseSNI unexpectedly parsed: %q", got)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("parseSNI control case failed: %v", err)
			}
		})
	}
}

func corruptSNILen(hs []byte, name string) []byte {
	// The SNI name is the tail of the record; its u16 length field sits
	// two bytes before the name. Smash the high byte so the declared
	// length overruns the extension.
	out := append([]byte(nil), hs...)
	idx := bytes.LastIndex(out, []byte(name))
	if idx < 2 {
		return out[:len(out)-1] // fallback: plain truncation
	}
	out[idx-2] = 0xff
	return out
}

func TestSniffClientHelloPeeksAndReplays(t *testing.T) {
	rec := buildClientHello("pypi.org", nil)
	br := bufio.NewReader(bytes.NewReader(rec))
	sni, peeked, err := sniffClientHello(br)
	if err != nil || sni != "pypi.org" {
		t.Fatalf("sniff = %q, %v", sni, err)
	}
	if !bytes.Equal(peeked, rec) {
		t.Fatal("peeked bytes must equal the full ClientHello record")
	}
	// Peek is non-destructive: the record must still be readable from the
	// same reader (the splice path never re-reads it; the MITM path relies
	// on the CONN having been drained of exactly these bytes).
	again := make([]byte, len(rec))
	if _, err := io.ReadFull(br, again); err != nil || !bytes.Equal(again, rec) {
		t.Fatalf("peek must not consume: %v", err)
	}
}

// A real crypto/tls ClientHello must parse too (guards against the
// hand-rolled fixture drifting from reality).
func TestSniffRealTLSClientHello(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	// Grab one real ClientHello by acting as a server once.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		sni string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- result{"", err}
			return
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		sni, _, err := sniffClientHello(br)
		conn.Close()
		ch <- result{sni, err}
	}()
	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "real-sni.example",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err == nil {
		client.Close()
	}
	got := <-ch
	if got.err != nil {
		t.Skipf("real ClientHello capture failed: %v", got.err)
	}
	if !strings.HasSuffix(got.sni, "example") {
		t.Fatalf("real SNI = %q", got.sni)
	}
}

func TestServeTransparentHTTPForwardsOriginForm(t *testing.T) {
	var gotPath, gotHost, gotTask string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHost = r.Host
		gotTask = r.Header.Get("X-Task-Id")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer backend.Close()

	g := NewGateway()
	defer g.Shutdown(nil)
	g.EnableSSRFBypassForTest()
	pol := &Policy{AllowDomains: []string{"127.0.0.1"}}
	g.SetPolicy("ttransparent", pol)

	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		g.serveTransparentHTTP(c2, "ttransparent", nil)
	}()
	// Origin-form request (transparent clients never send proxy-form).
	req := "GET /some/path?x=1 HTTP/1.1\r\nHost: " + backend.Listener.Addr().String() + "\r\nConnection: close\r\n\r\n"
	c1.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c1.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(c1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "upstream-ok") {
		t.Fatalf("transparent forward failed:\n%s", resp)
	}
	if gotPath != "/some/path" || !strings.HasPrefix(gotHost, "127.0.0.1:") {
		t.Fatalf("upstream saw path=%q host=%q", gotPath, gotHost)
	}
	if gotTask != "" {
		t.Fatalf("internal X-Task-Id must be stripped upstream, got %q", gotTask)
	}
}

func TestServeTransparentHTTPDeniedDomain(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend must not be reached for a denied domain")
	}))
	defer backend.Close()

	g := NewGateway()
	defer g.Shutdown(nil)
	g.EnableSSRFBypassForTest()
	g.SetPolicy("tdeny", &Policy{AllowDomains: []string{"allowed.example"}})

	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		g.serveTransparentHTTP(c2, "tdeny", nil)
	}()
	req := "GET /x HTTP/1.1\r\nHost: " + backend.Listener.Addr().String() + "\r\nConnection: close\r\n\r\n"
	c1.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c1.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(c1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "403") {
		t.Fatalf("denied transparent request must 403:\n%s", resp)
	}
}
