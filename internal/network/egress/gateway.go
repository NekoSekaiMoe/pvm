// Package egress implements the L7 network policy gateway (plan.md §4.2).
//
// It runs as a host-side HTTP proxy. Sandboxes are configured with
// HTTP_PROXY/HTTPS_PROXY pointing at it; every outbound request from the guest
// therefore flows through:
//
//	sandbox -> HTTP_CONNECT host:port -> Egress proxy
//	                                  -> domain/method/size/data-class decision
//	                                      ALLOW / BLOCK / REVIEW
//
// HTTPS uses CONNECT: the proxy sees the SNI/Host (the domain) but not the
// body — domain-level allow/deny is enforced without TLS MITM. HTTP bodies are
// inspected for size only (no deep content scan in the MVP; the DLP hook is a
// pluggable function).
//
// The eBPF TC filter (bpf/egress.c + internal/network/filter.go) remains as the
// IP-floor: it blocks RFC1918/loopback/link-local (SSRF) regardless of what the
// proxy allows, so a domain that resolves to an internal IP at connect time is
// still dropped.
package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"uml-container/internal/audit"
)

// Policy is the per-task egress rule set.
type Policy struct {
	AllowDomains     []string // exact match or "*.suffix" wildcard
	BlockDomains     []string // takes precedence over allow
	MaxRequestBody    int64   // bytes; 0 = unlimited
	MaxResponseBody   int64   // bytes; 0 = unlimited
	AllowedMethods   []string // default GET/HEAD/POST/PUT/DELETE/PATCH
	// ReviewHook is called for requests flagged as REVIEW (large POST, etc.).
	// If nil, REVIEW is treated as BLOCK.
	ReviewHook func(req *http.Request, bodySize int64) (allow bool, reason string)
}

// Decision is the outcome for a request.
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionBlock
	DecisionReview
)

// verdictString mirrors audit decisions for ledger rows.
func (d Decision) String() string {
	return [...]string{"allow", "block", "review"}[d]
}

// Gateway is the HTTP CONNECT proxy that enforces a Policy per task.
type Gateway struct {
	policies    map[string]*Policy // keyed by task id
	mu          sync.RWMutex
	ledger      *audit.Ledger // shared ledger; tasks separated by their own ledger
	bytesOut    map[string]*int64
	bytesOutMu  sync.Mutex
	server      *http.Server
	listener    net.Listener
}

// NewGateway constructs an empty gateway. Register policies with SetPolicy.
func NewGateway() *Gateway {
	return &Gateway{
		policies: make(map[string]*Policy),
		bytesOut: make(map[string]*int64),
	}
}

// SetPolicy installs/updates the egress policy for a task.
func (g *Gateway) SetPolicy(task string, p *Policy) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policies[task] = p
}

// AttachLedger wires an audit ledger so every egress decision is recorded.
func (g *Gateway) AttachLedger(l *audit.Ledger) { g.ledger = l }

// Listen starts the proxy on addr (e.g. "127.0.0.1:0" for ephemeral). Returns
// the actual address once bound.
func (g *Gateway) Listen(ctx context.Context, addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	g.listener = ln
	g.server = &http.Server{
		Handler: http.HandlerFunc(g.handle),
		// Tight timeouts: a sandbox should not hold a proxy idle for long.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go g.server.Serve(ln)
	return ln.Addr().String(), nil
}

// Shutdown stops the proxy.
func (g *Gateway) Shutdown(ctx context.Context) error {
	if g.server == nil {
		return nil
	}
	if ctx == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return g.server.Shutdown(ctx)
	}
	return g.server.Shutdown(ctx)
}

// Addr returns the bound address (empty if not listening).
func (g *Gateway) Addr() string {
	if g.listener == nil {
		return ""
	}
	return g.listener.Addr().String()
}

// handle dispatches CONNECT (HTTPS) and plain HTTP methods.
func (g *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	task := taskFromRequest(r)
	pol := g.policy(task)
	if pol == nil {
		// No policy registered -> default deny. The agent must have a policy
		// registered by the controller before any traffic can leave.
		g.record(task, r, DecisionBlock, "no policy registered")
		http.Error(w, "egress: no policy for task", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		g.handleConnect(w, r, task, pol)
		return
	}
	g.handleHTTP(w, r, task, pol)
}

// handleConnect implements the HTTPS CONNECT tunnel. We see the target host
// (from the CONNECT line) but not the encrypted body, so only domain-level
// policy is enforceable here. The eBPF floor still applies IP-block at TC.
func (g *Gateway) handleConnect(w http.ResponseWriter, r *http.Request, task string, pol *Policy) {
	host := anonymousPort(r.Host)
	d := g.decideDomain(host, pol)
	if d == DecisionBlock {
		g.record(task, r, d, "domain blocked")
		http.Error(w, "egress: blocked", http.StatusForbidden)
		return
	}
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		g.record(task, r, DecisionBlock, "dial failed: "+err.Error())
		http.Error(w, "egress: dial failed", http.StatusBadGateway)
		return
	}
	// SSRF floor check: refuse to tunnel to private IPs even if the proxy
	// allowed the domain (defense against DNS rebinding to internal IPs).
	if isPrivate(targetConn.RemoteAddr()) {
		targetConn.Close()
		g.record(task, r, DecisionBlock, "target resolved to private IP (SSRF floor)")
		http.Error(w, "egress: private IP blocked", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hj.Hijack()
	if err != nil {
		targetConn.Close()
		return
	}
	g.record(task, r, DecisionAllow, "CONNECT "+host)
	go pipe(clientConn, targetConn, task, g, pol)
	go pipe(targetConn, clientConn, task, g, pol)
}

// handleHTTP handles plain HTTP requests (body visible, method/size enforced).
func (g *Gateway) handleHTTP(w http.ResponseWriter, r *http.Request, task string, pol *Policy) {
	host := anonymousPort(r.Host)
	d := g.decideDomain(host, pol)
	if d == DecisionBlock {
		g.record(task, r, d, "domain blocked")
		http.Error(w, "egress: blocked", http.StatusForbidden)
		return
	}
	// method allowlist
	if !methodAllowed(r.Method, pol.AllowedMethods) {
		g.record(task, r, DecisionBlock, "method "+r.Method+" not allowed")
		http.Error(w, "egress: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// size cap on request body
	if pol.MaxRequestBody > 0 && r.ContentLength > pol.MaxRequestBody {
		g.record(task, r, DecisionBlock, fmt.Sprintf("request body %d > %d", r.ContentLength, pol.MaxRequestBody))
		http.Error(w, "egress: request too large", http.StatusRequestEntityTooLarge)
		return
	}
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "egress: bad request", http.StatusBadRequest)
		return
	}
	outReq.Header = r.Header.Clone()
	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		g.record(task, r, DecisionBlock, "upstream error: "+err.Error())
		http.Error(w, "egress: upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// size cap on response
	var src io.Reader = resp.Body
	if pol.MaxResponseBody > 0 {
		src = &io.LimitedReader{R: resp.Body, N: pol.MaxResponseBody}
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, src)
	g.addBytes(task, n)
	g.record(task, r, DecisionAllow, fmt.Sprintf("%s %s -> %d (%dB)", r.Method, host, resp.StatusCode, n))
}

// decideDomain applies block-over-allow with wildcard suffix matching.
func (g *Gateway) decideDomain(host string, pol *Policy) Decision {
	host = strings.ToLower(stripPort(host))
	for _, b := range pol.BlockDomains {
		if domainMatches(host, strings.ToLower(b)) {
			return DecisionBlock
		}
	}
	for _, a := range pol.AllowDomains {
		if domainMatches(host, strings.ToLower(a)) {
			return DecisionAllow
		}
	}
	return DecisionBlock // default deny
}

// domainMatches supports exact and "*.suffix" wildcard.
func domainMatches(host, rule string) bool {
	if rule == host {
		return true
	}
	if strings.HasPrefix(rule, "*.") {
		suffix := rule[1:] // ".suffix"
		return strings.HasSuffix(host, suffix)
	}
	return false
}

// methodAllowed defaults to a safe set if the policy lists none.
func methodAllowed(method string, allowed []string) bool {
	if len(allowed) == 0 {
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			return true
		}
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(a, method) {
			return true
		}
	}
	return false
}

// pipe shuttles bytes between two connections and accounts bytes.
func pipe(dst, src net.Conn, task string, g *Gateway, pol *Policy) {
	defer dst.Close()
	defer src.Close()
	n, _ := io.Copy(dst, src)
	g.addBytes(task, n)
}

// addBytes accumulates per-task egress bytes for budget enforcement.
func (g *Gateway) addBytes(task string, n int64) {
	g.bytesOutMu.Lock()
	defer g.bytesOutMu.Unlock()
	p, ok := g.bytesOut[task]
	if !ok {
		p = new(int64)
		g.bytesOut[task] = p
	}
	atomic.AddInt64(p, n)
}

// BytesUsed returns total egress bytes accounted to a task.
func (g *Gateway) BytesUsed(task string) int64 {
	g.bytesOutMu.Lock()
	defer g.bytesOutMu.Unlock()
	if p, ok := g.bytesOut[task]; ok {
		return atomic.LoadInt64(p)
	}
	return 0
}

// PolicyForTask returns the registered policy for a task (read-only copy of the
// pointer). Used by integration tests and observability tooling to confirm what
// policy is in effect without issuing real traffic.
func (g *Gateway) PolicyForTask(task string) *Policy {
	return g.policy(task)
}

// taskFromRequest extracts the task identifier. Sandboxes MUST send
// "X-Task-Id" header (the controller injects it into the guest env); without
// it, the request is denied (can't attribute the traffic).
func taskFromRequest(r *http.Request) string {
	return r.Header.Get("X-Task-Id")
}

func (g *Gateway) policy(task string) *Policy {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.policies[task]
}

func (g *Gateway) record(task string, r *http.Request, d Decision, reason string) {
	if g.ledger == nil {
		return
	}
	_ = g.ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  r.RemoteAddr,
		Action:   r.Method + " " + stripPort(r.Host),
		Params:   map[string]interface{}{"task": task, "bytes": r.ContentLength},
		Decision: audit.Decision(d.String()),
		Reason:   reason,
	})
}

// --- helpers ---

// isPrivate reports whether a TCP address resolves to RFC1918 / loopback /
// link-local — the SSRF floor. Mirrors bpf/egress.c's behavior at L3.
func isPrivate(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip := tcp.IP
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}

func stripPort(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[:i]
	}
	return hostport
}

// anonymousPort strips the port from a host for logging (privacy/DLP-lite).
func anonymousPort(host string) string {
	return stripPort(host)
}

var _ = bufio.NewReader // keep import for future streaming body scan
var _ = errors.New
var _ = log.Print
