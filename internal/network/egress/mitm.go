package egress

// mitm.go implements opt-in TLS interception for the egress gateway
// (bucket-2 gap "HTTPS CONNECT 不透明无法注入"): rules marked mitm=true and
// carrying Inject terminate the guest's TLS with a leaf certificate signed
// by the pvm egress CA, apply the full L7 pipeline (decide → inject →
// audit) on the plaintext, and re-encrypt to the real upstream with the
// correct SNI. The CA is generated once per host (state dir, 0600) and must
// be trusted by the guest rootfs (same operational model as CubeSandbox's
// CubeEgress CA provisioning); an untrusting guest fails the handshake —
// credentials never travel a path the CA cannot protect.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA is the egress MITM certificate authority.
type CA struct {
	mu     sync.Mutex
	leaf   *x509.Certificate
	priv   *ecdsa.PrivateKey
	leaves map[string]tls.Certificate
	dir    string
}

// LoadOrCreateCA loads (or generates) the CA under dir (ca.key / ca.crt).
// The private key is parsed eagerly so a corrupted key file fails here,
// not mid-interception.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("egress ca: %w", err)
	}
	keyPath := filepath.Join(dir, "ca.key")
	crtPath := filepath.Join(dir, "ca.crt")

	priv, leaf, err := loadCAFiles(keyPath, crtPath)
	if err == nil {
		return &CA{leaf: leaf, priv: priv, leaves: map[string]tls.Certificate{}, dir: dir}, nil
	}
	if !os.IsNotExist(err) && err != errCAPartial {
		// Present but unreadable/corrupt: never silently regenerate — a new
		// CA would invalidate every guest trust store that pinned the old.
		return nil, fmt.Errorf("egress ca: %w", err)
	}

	// Generate a fresh CA (ECDSA P-256, 10 years).
	gen, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if gerr != nil {
		return nil, gerr
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "PVM Egress CA", Organization: []string{"pvm"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, cerr := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &gen.PublicKey, gen)
	if cerr != nil {
		return nil, cerr
	}
	keyDER, merr := x509.MarshalECPrivateKey(gen)
	if merr != nil {
		return nil, merr
	}
	if werr := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); werr != nil {
		return nil, werr
	}
	if werr := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); werr != nil {
		return nil, werr
	}
	parsed, _ := x509.ParseCertificate(der)
	return &CA{leaf: parsed, priv: gen, leaves: map[string]tls.Certificate{}, dir: dir}, nil
}

// errCAPartial marks "one of the two files is missing".
var errCAPartial = fmt.Errorf("ca key/crt pair incomplete")

func loadCAFiles(keyPath, crtPath string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	keyPEM, kerr := os.ReadFile(keyPath)
	crtPEM, cerr := os.ReadFile(crtPath)
	if kerr != nil || cerr != nil {
		return nil, nil, errCAPartial
	}
	kb, _ := pem.Decode(keyPEM)
	cb, _ := pem.Decode(crtPEM)
	if kb == nil || cb == nil {
		return nil, nil, fmt.Errorf("malformed CA pem")
	}
	priv, perr := x509.ParseECPrivateKey(kb.Bytes)
	if perr != nil {
		return nil, nil, perr
	}
	leaf, lerr := x509.ParseCertificate(cb.Bytes)
	if lerr != nil {
		return nil, nil, lerr
	}
	return priv, leaf, nil
}

// Leaf returns (creating and caching) a server certificate for host signed
// by the CA.
func (ca *CA) Leaf(host string) (tls.Certificate, error) {
	host = stripPortMITM(host)
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leaves[host]; ok {
		return c, nil
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"pvm-mitm"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.leaf, &ca.priv.PublicKey, ca.priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: ca.priv}
	if len(ca.leaves) > 256 {
		ca.leaves = map[string]tls.Certificate{} // bound the cache
	}
	ca.leaves[host] = cert
	return cert, nil
}

// EnableMITM arms the gateway's CA (required before MITM rules activate).
func (g *Gateway) EnableMITM(ca *CA) {
	g.mu.Lock()
	g.mitmCA = ca
	g.mu.Unlock()
}

// MITMArmed reports whether a CA is present (introspection for tests/API).
func (g *Gateway) MITMArmed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.mitmCA != nil
}

// ruleMITM returns the first rule that matches the CONNECT target and
// requires interception (mitm=true + Inject).
func (g *Gateway) ruleMITM(host string, pol *Policy) *EgressRule {
	host = stripPortMITM(host)
	for i := range pol.Rules {
		r := &pol.Rules[i]
		if r.MITM == nil || !*r.MITM || r.Inject == nil {
			continue
		}
		name := r.SNI
		if name == "" {
			name = r.Host
		}
		if name == "" || domainMatches(host, strings.ToLower(name)) {
			return r
		}
	}
	return nil
}

func stripPortMITM(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// serveMITM drives the intercepted connection: answer the CONNECT, accept
// the guest's TLS with a CA leaf, then proxy inner requests through the
// gateway's normal decide/inject/audit pipeline over a real TLS upstream.
func (g *Gateway) serveMITM(clientConn net.Conn, brw *bufio.ReadWriter, task, host string, pol *Policy) {
	defer clientConn.Close()
	g.mu.Lock()
	ca := g.mitmCA
	g.mu.Unlock()
	if ca == nil {
		fmt.Fprint(brw, "HTTP/1.1 500 egress: MITM rule matched but no CA armed (EnableMITM)\r\n\r\n")
		brw.Flush()
		return
	}

	fmt.Fprint(brw, "HTTP/1.1 200 Connection Established\r\n\r\n")
	brw.Flush()

	// Bytes the guest pipelined past the 200 (an eager ClientHello) are
	// already sitting in the hijacked bufio.Reader; the TLS server must see
	// them before reading the raw connection. Mirror the raw-tunnel drain
	// in handleConnect instead of losing the handshake bytes.
	tlsSrc := net.Conn(clientConn)
	if n := brw.Reader.Buffered(); n > 0 {
		tlsSrc = &prefixedConn{Conn: clientConn, r: io.MultiReader(io.LimitReader(brw.Reader, int64(n)), clientConn)}
	}
	tlsConn := tls.Server(tlsSrc, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = stripPortMITM(host)
			}
			c, lerr := ca.Leaf(name)
			if lerr != nil {
				return nil, lerr
			}
			return &c, nil
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		g.record(task, &http.Request{Host: host, RequestURI: "mitm:" + host, Method: http.MethodConnect}, DecisionBlock, "mitm handshake failed: "+err.Error())
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)
	writer := bufio.NewWriter(tlsConn)
	for {
		req, rerr := http.ReadRequest(reader)
		if rerr != nil {
			return
		}
		req.URL.Host = host
		req.URL.Scheme = "https"
		req.RequestURI = "" // client-style field; must be cleared to forward

		v := viewFromHTTP(req)
		d := g.decideDomain(v, pol)
		if d == DecisionBlock {
			writeMITMError(writer, http.StatusForbidden, "egress: blocked by rule")
			continue
		}
		if d == DecisionReview && pol.ReviewHook != nil {
			allow, reason := pol.ReviewHook(req, 0)
			if !allow {
				g.record(task, req, DecisionBlock, "mitm review denied: "+reason)
				writeMITMError(writer, http.StatusForbidden, "egress: review denied")
				continue
			}
		}
		g.ApplyInject(req, v, pol)
		g.addBytes(task, contentLengthOf(req))
		g.record(task, req, DecisionAllow, "mitm proxied")

		outReq, oerr := http.NewRequest(req.Method, req.URL.String(), req.Body)
		if oerr != nil {
			writeMITMError(writer, http.StatusBadGateway, "egress: bad request")
			continue
		}
		outReq.Header = stripInternalHeaders(req.Header.Clone())
		resp, terr := g.transportForTask(task, stripPortMITM(host)).RoundTrip(outReq)
		if terr != nil {
			writeMITMError(writer, http.StatusBadGateway, "egress: upstream error: "+terr.Error())
			continue
		}
		resp.Write(writer)
		writer.Flush()
		resp.Body.Close()
	}
}

// writeMITMError streams a minimal error response on the intercepted conn.
func writeMITMError(w *bufio.Writer, code int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\n%s", code, http.StatusText(code), len(msg), msg)
	w.Flush()
}

// prefixedConn serves buffered pre-handshake bytes (see serveMITM) before
// delegating reads to the underlying connection.
type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixedConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func contentLengthOf(req *http.Request) int64 {
	if req.ContentLength > 0 {
		return req.ContentLength
	}
	return 0
}
