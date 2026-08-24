package dnslearn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// maxInFlightQueries bounds concurrent upstream queries the proxy forwards;
// beyond it queries are dropped (DNS clients retry). This keeps a guest
// spray of lookups from pinning one goroutine + upstream socket each.
const maxInFlightQueries = 64

// upstreamTimeout bounds a single forwarded query. Stub resolvers retransmit
// after ~5s, so 3s keeps the proxy snappier than its clients.
const upstreamTimeout = 3 * time.Second

// Proxy is a per-task UDP DNS front-end: it forwards queries to the
// configured upstream resolver and snoops the A-record answers into the
// Learner. It is deliberately transparent — queries are relayed verbatim and
// only the (successful) responses are observed — so a guest sees stock DNS
// semantics whether or not learning is enabled.
type Proxy struct {
	learner  *Learner
	upstream string
	conn     *net.UDPConn
	inFlight chan struct{}

	closeOnce sync.Once
	closed    chan struct{}
}

// StartProxy binds the task's DNS proxy and starts serving. preferBind is
// the ideal address (the task's gateway IP, port 53 — where a guest's
// default resolver points); when it cannot be bound (port 53 needs
// CAP_NET_BIND_SERVICE, and in rootless/degraded runs the gateway IP does
// not exist on the host at all) the proxy falls back to 127.0.0.1:0,
// records a security:degraded_warning, and reports the actual address. If
// even the loopback fallback fails, the error propagates: the caller
// (StartTask) audits the warning and continues WITHOUT DNS learning — the
// L7 egress proxy still enforces.
func (l *Learner) StartProxy(ctx context.Context, preferBind string) (string, error) {
	l.mu.Lock()
	if l.proxy != nil {
		addr := l.proxy.conn.LocalAddr().String()
		l.mu.Unlock()
		return addr, nil
	}
	l.mu.Unlock()

	conn, err := listenUDP(preferBind)
	if err != nil && preferBind != "" {
		l.AuditDegraded(fmt.Sprintf(
			"dns proxy bind %s failed (%v); falling back to loopback ephemeral "+
				"(guest DNS will NOT be snooped — learning only via promote/API)",
			preferBind, err))
		conn, err = listenUDP("127.0.0.1:0")
	}
	if err != nil {
		return "", fmt.Errorf("dnslearn: bind dns proxy: %w", err)
	}

	p := &Proxy{
		learner:  l,
		upstream: l.upstream,
		conn:     conn,
		inFlight: make(chan struct{}, maxInFlightQueries),
		closed:   make(chan struct{}),
	}
	l.mu.Lock()
	if l.closed { // Close raced with StartProxy
		l.mu.Unlock()
		conn.Close()
		return "", fmt.Errorf("dnslearn: learner closed")
	}
	l.proxy = p
	l.mu.Unlock()

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		p.serve()
	}()
	// Close the socket on ctx cancel so serve() exits even without Close().
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		if ctx != nil {
			select {
			case <-ctx.Done():
				p.Close()
			case <-p.closed:
			}
		} else {
			<-p.closed
		}
	}()
	return conn.LocalAddr().String(), nil
}

// Addr reports the proxy's bound address, or "" when not started.
func (l *Learner) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.proxy == nil {
		return ""
	}
	return l.proxy.conn.LocalAddr().String()
}

// listenUDP parses "ip:port" (bare IP implies :53) and binds it.
func listenUDP(bind string) (*net.UDPConn, error) {
	if _, _, err := net.SplitHostPort(bind); err != nil {
		if ip := net.ParseIP(bind); ip != nil {
			bind = net.JoinHostPort(bind, "53")
		}
	}
	addr, err := net.ResolveUDPAddr("udp", bind)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", addr)
}

// serve relays datagrams until the socket is closed.
func (p *Proxy) serve() {
	for {
		buf := make([]byte, dnsProxyBufferSize)
		n, client, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return // closed
		}
		select {
		case p.inFlight <- struct{}{}:
			go p.forward(buf[:n], client)
		default:
			// In-flight cap reached: drop. The stub resolver retransmits.
		}
	}
}

// forward relays one query to the upstream resolver, snoops the A-record
// answers of the response into the learner, and relays the response back
// verbatim. Any failure drops the query — the stub resolver retransmits.
func (p *Proxy) forward(query []byte, client *net.UDPAddr) {
	defer func() { <-p.inFlight }()
	qname, qok := firstQuestionName(query)
	conn, err := net.DialTimeout("udp", p.upstream, upstreamTimeout)
	if err != nil {
		return // upstream unreachable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(upstreamTimeout))
	if _, err := conn.Write(query); err != nil {
		return
	}
	buf := make([]byte, dnsProxyBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	resp := buf[:n]
	// Relay only the response to OUR forwarded query (id match guards the
	// shared upstream socket against cross-talk), and snoop that same
	// response.
	if len(query) < 2 || len(resp) < 2 ||
		binary.BigEndian.Uint16(resp[:2]) != binary.BigEndian.Uint16(query[:2]) {
		return
	}
	if qok {
		if ips, ttl, ok := parseAResponse(resp); ok && len(ips) > 0 {
			p.learner.ProcessResponse(qname, ips, ttl)
		}
	}
	_, _ = p.conn.WriteToUDP(resp, client) // best-effort (may race Close)
}

// Close shuts the proxy down. Idempotent; safe to call concurrently.
func (p *Proxy) Close() {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.conn.Close()
	})
}

// --- wire parsing (golang.org/x/net/dns/dnsmessage) ----------------------
//
// golang.org/x/net is already a module dependency (previously indirect via
// the docker stack); using its dnsmessage parser avoids a new heavy dep
// (miekg/dns) for the handful of message types we touch.

// firstQuestionName extracts the question name of a DNS query message.
func firstQuestionName(msg []byte) (string, bool) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(msg); err != nil {
		return "", false
	}
	q, err := parser.Question()
	if err != nil {
		return "", false
	}
	return q.Name.String(), true
}

// parseAResponse extracts the A-record answers of a DNS response: the IPs
// and the MINIMUM TTL across them (the safest cache lifetime — no answer
// outlives the freshest guarantee any of its records gave). AAAA answers are
// skipped on purpose: the BPF whitelist is IPv4-only (see package doc).
func parseAResponse(msg []byte) (ips []net.IP, minTTL uint32, ok bool) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(msg); err != nil {
		return nil, 0, false
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, 0, false
	}
	first := true
	for {
		hdr, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, 0, false
		}
		if hdr.Type != dnsmessage.TypeA {
			if err := parser.SkipAnswer(); err != nil {
				return nil, 0, false
			}
			continue
		}
		// x/net v0.25 has no Parser.AAResource; Answer() unpacks the body.
		res, err := parser.Answer()
		if err != nil {
			return nil, 0, false
		}
		ar, ok2 := res.Body.(*dnsmessage.AResource)
		if !ok2 {
			continue
		}
		ips = append(ips, net.IP(ar.A[:]))
		if first || hdr.TTL < minTTL {
			minTTL = hdr.TTL
		}
		first = false
	}
	return ips, minTTL, true
}

// queryA performs one UDP A-record lookup against upstream and returns the
// parsed answers. Used by LearnNow (the promote API's "learn immediately")
// so a freshly allowed domain does not have to wait for guest traffic.
func queryA(upstream, domain string) (ips []net.IP, minTTL uint32, err error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	name := domain
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	dn, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, 0, fmt.Errorf("dnslearn: invalid domain %q: %w", domain, err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: id, RecursionDesired: true,
	})
	if err := builder.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name: dn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, 0, err
	}
	query, err := builder.Finish()
	if err != nil {
		return nil, 0, err
	}

	conn, err := net.DialTimeout("udp", upstream, upstreamTimeout)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(upstreamTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, dnsProxyBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	resp := buf[:n]
	// Basic spoof hygiene: the response must answer OUR query id.
	if len(resp) < 2 || binary.BigEndian.Uint16(resp[:2]) != id {
		return nil, 0, fmt.Errorf("dnslearn: upstream response id mismatch")
	}
	ips, minTTL, ok := parseAResponse(resp)
	if !ok {
		return nil, 0, fmt.Errorf("dnslearn: unparsable upstream response")
	}
	return ips, minTTL, nil
}

// LearnNow resolves domain against the upstream resolver and feeds the
// answer through the same allowlist-guarded path as snooped traffic.
// Returns the number of entries inserted/refreshed. A non-allowlisted
// domain is an error (never resolved, never learned).
func (l *Learner) LearnNow(domain string) (int, error) {
	if !l.IsAllowlisted(domain) {
		return 0, fmt.Errorf("dnslearn: domain %q not in allowlist", domain)
	}
	ips, ttl, err := queryA(l.upstream, normalizeName(domain))
	if err != nil {
		return 0, err
	}
	return l.ProcessResponse(domain, ips, ttl), nil
}

// --- upstream default resolution -----------------------------------------

// normalizeUpstream validates/normalizes the configured upstream ("IP" or
// "IP:port"); empty selects the system resolver.
func normalizeUpstream(up string) (string, error) {
	if up == "" {
		return defaultUpstream(), nil
	}
	if ip := net.ParseIP(up); ip != nil {
		return net.JoinHostPort(up, "53"), nil
	}
	host, port, err := net.SplitHostPort(up)
	if err != nil {
		return "", fmt.Errorf("dnslearn: upstream %q must be IP or IP:port: %w", up, err)
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("dnslearn: upstream host %q is not an IP", host)
	}
	return net.JoinHostPort(host, port), nil
}

// defaultUpstream returns the first nameserver in /etc/resolv.conf, falling
// back to 1.1.1.1 (a deliberate, documented default — not ambient magic).
func defaultUpstream() string {
	if ns := firstNameserver("/etc/resolv.conf"); ns != "" {
		return net.JoinHostPort(ns, "53")
	}
	return "1.1.1.1:53"
}

// firstNameserver scans an /etc/resolv.conf-style file for the first
// "nameserver <ip>" line with a parseable IP.
func firstNameserver(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil {
			return fields[1]
		}
	}
	return ""
}
