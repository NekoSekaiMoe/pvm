package egress

// transparent.go — transparent interception data path.
//
// In the bridge dataplane, iptables REDIRECT steers the guest's outbound
// TCP :80/:443 into a per-task transparent listener (no client-side proxy
// configuration; see internal/network's EnableTransparentL7). For every
// accepted connection the ORIGINAL destination is recovered from the conn
// via getsockopt(SO_ORIGINAL_DST), then:
//
//   - TLS (first byte 0x16): the ClientHello is sniffed for its SNI. A
//     denied SNI closes the connection; a rule opting into MITM terminates
//     TLS with the gateway CA and hands the decrypted stream to the normal
//     L7 pipeline (full method/path/injection enforcement); anything else
//     splices the raw bytes to the original destination through the same
//     SSRF-floor + rebinding-guard dial checks the CONNECT tunnel uses.
//   - plain HTTP: requests are served through the standard gateway
//     pipeline (handleHTTP) with origin-form requests upgraded by setting
//     URL.Host from the Host header — identical policy, caps, billing and
//     audit semantics to explicit-proxy traffic.
//
// The X-Task-Id header is injected into the (synthesized) request so the
// shared pipeline attributes and audits everything to the right task; it
// is stripped again before anything leaves the host (stripInternalHeaders).

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
	"unsafe"

	"uml-container/internal/audit"

	"golang.org/x/sys/unix"
)

// ErrNoOriginalDst marks a connection whose original destination cannot be
// recovered (not REDIRECTed, IPv6, closed early).
var ErrNoOriginalDst = errors.New("egress: transparent: SO_ORIGINAL_DST unavailable")

// originalDstAddr recovers the pre-REDIRECT destination of a TCP conn.
func originalDstAddr(conn net.Conn) (*net.TCPAddr, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, ErrNoOriginalDst
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return nil, ErrNoOriginalDst
	}
	var sockaddr [16]byte // sockaddr_in
	var errno unix.Errno
	ctrlErr := raw.Control(func(fd uintptr) {
		length := uint64(len(sockaddr))
		_, _, errno = unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.IPPROTO_IP),
			uintptr(unix.SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&sockaddr)),
			uintptr(unsafe.Pointer(&length)),
			0,
		)
	})
	if ctrlErr != nil || errno != 0 {
		return nil, ErrNoOriginalDst
	}
	// sockaddr_in: family(2) port(2, network order) addr(4) zero(8).
	if binary.BigEndian.Uint16(sockaddr[0:2]) != unix.AF_INET {
		return nil, ErrNoOriginalDst
	}
	port := binary.BigEndian.Uint16(sockaddr[2:4])
	ip := net.IPv4(sockaddr[4], sockaddr[5], sockaddr[6], sockaddr[7])
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}

// oneConnListener adapts a single net.Conn to net.Listener so an
// http.Server can serve exactly one connection.
type oneConnListener struct {
	conn net.Conn
	done bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, http.ErrServerClosed
	}
	l.done = true
	return l.conn, nil
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// transparentAcceptLoop accepts raw connections and runs the decision
// tree on each (the listener carries no http.Server in this mode).
func (g *Gateway) transparentAcceptLoop(taskID string, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Closed listener: task teardown, exit quietly.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient failures (EMFILE/ENFILE while the task spawns
			// processes, brief timeouts) must NOT kill the interception
			// loop — the REDIRECT rules stay installed, so a dead accept
			// loop would blackhole the task's :80/:443 traffic until
			// re-listen. Back off and retry; the closed-listener check
			// above is the only clean exit.
			var ne net.Error
			delay := 100 * time.Millisecond
			if errors.As(err, &ne) && ne.Timeout() {
				delay = 5 * time.Millisecond
			}
			time.Sleep(delay)
			continue
		}
		go g.serveTransparent(conn, taskID)
	}
}

// ListenTransparentForTask binds a WILDCARD listener for taskID and serves
// transparently-redirected connections. The returned listener's port is
// what iptables REDIRECT targets (network.EnableTransparentL7).
//
// No policy is auto-registered here on purpose: a task without a
// registered policy is BLOCKED by serveTransparent, exactly like the
// CONNECT proxy path (gateway.go's "no policy registered" refusal) —
// one fail-closed semantic for both planes. Callers that want traffic
// to flow must SetPolicy first (the container manager always does,
// before creating this listener).
func (g *Gateway) ListenTransparentForTask(ctx context.Context, taskID string) (*taskListener, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	tl := &taskListener{
		taskID:   taskID,
		addr:     ln.Addr().String(),
		listener: ln,
		gateway:  g,
	}
	go g.transparentAcceptLoop(taskID, ln)
	return tl, nil
}

// serveTransparent runs one accepted connection through the decision tree
// described in the file comment.
func (g *Gateway) serveTransparent(conn net.Conn, taskID string) {
	defer conn.Close()
	dst, err := originalDstAddr(conn)
	if err != nil {
		return // not redirected here: nothing we can attribute
	}
	pol := g.policy(taskID)
	if pol == nil {
		g.recordRaw(taskID, "transparent", DecisionBlock, "no policy registered")
		return
	}

	br := bufio.NewReader(conn)
	head, err := br.Peek(1)
	if err != nil {
		return
	}
	if head[0] == 0x16 { // TLS ClientHello
		g.serveTransparentTLS(conn, br, taskID, dst, pol)
		return
	}
	g.serveTransparentHTTP(conn, taskID, dst)
}

// serveTransparentHTTP runs origin-form HTTP through the shared pipeline:
// the one-conn http.Server frames requests, the wrapper upgrades them to
// proxy-form (absolute URL from the Host header) and injects X-Task-Id so
// handle() attributes and audits correctly.
func (g *Gateway) serveTransparentHTTP(conn net.Conn, taskID string, dst *net.TCPAddr) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Task-Id", taskID)
		if r.URL.Host == "" {
			host := r.Host
			if host == "" {
				host = dst.String()
			}
			r.URL.Scheme = "http"
			r.URL.Host = host
			r.RequestURI = "" // server-form: net/http refuses proxy-form forwarding
		}
		g.handle(w, r)
	})
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
	}
	_ = srv.Serve(&oneConnListener{conn: conn})
}

// serveTransparentTLS sniffs the SNI and either MITMs (rule opted in),
// splices (allowed), or drops (denied).
func (g *Gateway) serveTransparentTLS(conn net.Conn, br *bufio.Reader, taskID string, dst *net.TCPAddr, pol *Policy) {
	sni, clientHello, err := sniffClientHello(br)
	if err != nil {
		g.recordRaw(taskID, "transparent-tls", DecisionBlock, "unreadable ClientHello: "+err.Error())
		return
	}
	v := requestView{scheme: "https", host: sni, port: strconv.Itoa(dst.Port)}
	if g.decideDomain(v, pol) == DecisionBlock {
		g.recordRaw(taskID, "transparent-tls", DecisionBlock, "domain blocked: "+sni)
		return
	}
	if g.ruleMITM(sni, pol) != nil {
		// Replay the buffered ClientHello: serveMITM reads the handshake
		// itself from the connection + bufio pair.
		replay := &prefixedConn{Conn: conn, r: io.MultiReader(bytesReader(clientHello), conn)}
		brw := &bufio.ReadWriter{Reader: bufio.NewReader(replay), Writer: bufio.NewWriter(replay)}
		g.serveMITM(replay, brw, taskID, sni, pol)
		return
	}
	// Raw splice to the original destination, with the same dial checks as
	// the CONNECT tunnel (SSRF floor + DNS-learned rebinding guard).
	target, err := net.DialTimeout("tcp", dst.String(), 10*time.Second)
	if err != nil {
		g.recordRaw(taskID, "transparent-tls", DecisionBlock, "dial failed: "+err.Error())
		return
	}
	defer target.Close()
	if g.ssrFloorEnabled() && isPrivate(target.RemoteAddr()) {
		g.recordRaw(taskID, "transparent-tls", DecisionBlock, "target is private IP (SSRF floor)")
		return
	}
	if set := g.learnedDialSet(taskID, sni); set != nil && !learnedSetContainsIP(set, target.RemoteAddr()) {
		g.recordRaw(taskID, "transparent-tls", DecisionBlock, "dialed IP not in DNS-learned set (rebinding guard)")
		return
	}
	if _, err := target.Write(clientHello); err != nil {
		return
	}
	g.trackTunnel(taskID, conn)
	defer g.untrackTunnel(taskID, conn)
	up := &countingConn{Conn: target, task: taskID, g: g}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
	<-done
	<-done
}

// bytesReader avoids pulling bytes.Buffer in for one call site.
func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b []byte
	i int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// sniffClientHello peeks exactly one TLS record's worth of the ClientHello
// and extracts the SNI server_name. Returns the raw peeked bytes so the
// caller can replay them upstream (or into the MITM path).
func sniffClientHello(br *bufio.Reader) (string, []byte, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", nil, err
	}
	if hdr[0] != 0x16 {
		return "", nil, fmt.Errorf("not a handshake record (type 0x%02x)", hdr[0])
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 44 || recLen > 1<<16 {
		return "", nil, fmt.Errorf("implausible record length %d", recLen)
	}
	full, err := br.Peek(5 + recLen)
	if err != nil {
		return "", nil, err
	}
	sni, err := parseSNI(full[5:])
	if err != nil {
		return "", nil, err
	}
	return sni, full, nil
}

// parseSNI walks a TLS handshake body (ClientHello) to the SNI extension.
// Bounds-checked throughout: a malformed ClientHello must not panic the
// gateway.
func parseSNI(hs []byte) (string, error) {
	if len(hs) < 44 || hs[0] != 0x01 {
		return "", errors.New("not a ClientHello")
	}
	p := 4 + 2 + 32 // handshake header + client_version + random
	readU16 := func() (uint16, error) {
		if p+2 > len(hs) {
			return 0, errors.New("truncated ClientHello")
		}
		v := binary.BigEndian.Uint16(hs[p : p+2])
		p += 2
		return v, nil
	}
	readU8 := func() (byte, error) {
		if p >= len(hs) {
			return 0, errors.New("truncated ClientHello")
		}
		v := hs[p]
		p++
		return v, nil
	}
	skip := func(n int) error {
		if n < 0 || p+n > len(hs) {
			return errors.New("truncated ClientHello")
		}
		p += n
		return nil
	}
	sidLen, err := readU8()
	if err != nil {
		return "", err
	}
	if err := skip(int(sidLen)); err != nil {
		return "", err
	}
	csLen, err := readU16()
	if err != nil {
		return "", err
	}
	if err := skip(int(csLen)); err != nil {
		return "", err
	}
	cmLen, err := readU8()
	if err != nil {
		return "", err
	}
	if err := skip(int(cmLen)); err != nil {
		return "", err
	}
	extTotal, err := readU16()
	if err != nil {
		return "", err
	}
	extEnd := p + int(extTotal)
	if extEnd > len(hs) {
		return "", errors.New("extension block overruns record")
	}
	for p+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hs[p : p+2])
		extLen := int(binary.BigEndian.Uint16(hs[p+2 : p+4]))
		p += 4
		if extLen < 0 || p+extLen > extEnd {
			return "", errors.New("extension overruns block")
		}
		if extType == 0x0000 { // server_name
			body := hs[p : p+extLen]
			// SNI list: entry count(2) then entries: type(1) len(2) name.
			if len(body) >= 5 && body[2] == 0x00 {
				nameLen := int(binary.BigEndian.Uint16(body[3:5]))
				if 5+nameLen > len(body) {
					return "", errors.New("SNI name overruns extension")
				}
				return string(body[5 : 5+nameLen]), nil
			}
			return "", errors.New("malformed SNI extension")
		}
		p += extLen
	}
	return "", errors.New("no SNI extension")
}

// recordRaw audits a decision that has no *http.Request to hang it on
// (raw TLS handshakes, pre-framing failures). Mirrors g.record's shape.
func (g *Gateway) recordRaw(task, op string, d Decision, reason string) {
	if d == DecisionBlock {
		g.addDenied(task)
	}
	g.mu.RLock()
	l := g.ledger
	if tl, ok := g.ledgers[task]; ok && tl != nil {
		l = tl
	}
	g.mu.RUnlock()
	if l == nil {
		return
	}
	if err := l.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  "transparent",
		Action:   op,
		Params:   map[string]interface{}{"task": task},
		Decision: audit.Decision(d.String()),
		Reason:   reason,
	}); err != nil {
		log.Printf("egress: audit append failed for task %s: %v", task, err)
	}
}

// countingConn wraps the upstream splice direction so transparent TLS
// tunnels bill the same sandbox→upstream bytes as the CONNECT tunnel.
type countingConn struct {
	net.Conn
	task string
	g    *Gateway
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.g.addBytes(c.task, int64(n))
	}
	return n, err
}
