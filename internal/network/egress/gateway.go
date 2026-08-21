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
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"uml-container/internal/audit"
)

// Policy is the per-task egress rule set.
type Policy struct {
	AllowDomains    []string // exact match or "*.suffix" wildcard
	BlockDomains    []string // takes precedence over allow
	MaxRequestBody  int64    // bytes; 0 = unlimited
	MaxResponseBody int64    // bytes; 0 = unlimited
	AllowedMethods  []string // default GET/HEAD/POST/PUT/DELETE/PATCH
	// ReviewHook is called for requests flagged as REVIEW (large POST, etc.).
	// If nil, REVIEW is treated as BLOCK.
	ReviewHook func(req *http.Request, bodySize int64) (allow bool, reason string)
	// Rules is the extended L7 set (Cube parity: security-proxy.md). When
	// non-empty, rule decisions take precedence over the flat AllowDomains
	// allowlist. BlockDomains is always evaluated first and can never be
	// overridden by a rule; when Rules is empty the flat lists decide.
	Rules []EgressRule
}

// EgressRule mirrors spec.EgressRule at the gateway layer to avoid an
// import cycle (spec -> egress would be circular).
type EgressRule struct {
	Name   string
	Host   string
	SNI    string
	Method []string
	Path   string // exact or "/prefix/*"
	Scheme string // "http" | "https"
	Port   int
	Allow  *bool
	Inject *EgressInject
}

// EgressInject mirrors spec.EgressInject.
type EgressInject struct {
	Header string
	Format string // e.g. "Bearer ${SECRET}"
	Secret string
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
	policies   map[string]*Policy // keyed by task id
	mu         sync.RWMutex
	ledger     *audit.Ledger            // default ledger (single-task or legacy)
	ledgers    map[string]*audit.Ledger // per-task ledgers (take precedence)
	bytesOut   map[string]*int64
	bytesOutMu sync.Mutex
	server     *http.Server
	listener   net.Listener

	// ssrfBypass is a test-only escape hatch that disables the SSRF IP-floor
	// on handleHTTP so unit tests can point at httptest's 127.0.0.1 backends.
	// Production code MUST NOT set this; it's unexported and only written via
	// EnableSSRFBypassForTest.
	ssrfBypass bool
}

// NewGateway constructs an empty gateway. Register policies with SetPolicy.
func NewGateway() *Gateway {
	return &Gateway{
		policies: make(map[string]*Policy),
		ledgers:  make(map[string]*audit.Ledger),
		bytesOut: make(map[string]*int64),
	}
}

// EnableSSRFBypassForTest disables the SSRF IP-floor on handleHTTP. It exists
// so unit tests can route to httptest.NewServer (which binds 127.0.0.1) without
// being blocked by the floor. Production callers MUST NOT use it; the SSRF
// floor is a load-bearing security control.
func (g *Gateway) EnableSSRFBypassForTest() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ssrfBypass = true
}

// SetPolicy installs/updates the egress policy for a task.
func (g *Gateway) SetPolicy(task string, p *Policy) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policies[task] = p
}

// AttachLedger wires a fallback audit ledger so every egress decision is
// recorded. For gateways that serve multiple tasks, prefer AttachTaskLedger
// so each task's traffic lands in its own ledger.
func (g *Gateway) AttachLedger(l *audit.Ledger) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ledger = l
}

// AttachTaskLedger wires a task-specific ledger. When present, it takes
// precedence over the gateway-wide ledger for that task's records, so a
// shared gateway doesn't misattribute traffic to the controller process's
// default task.
func (g *Gateway) AttachTaskLedger(task string, l *audit.Ledger) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ledgers[task] = l
}

// Listen starts the proxy on addr (e.g. "127.0.0.1:0" for ephemeral). Returns
// the actual address once bound. The shared listener attributes traffic via
// the guest-supplied X-Task-Id header, which is appropriate for tests and
// single-tenant setups but is NOT a trustworthy attribution source in
// production (a malicious guest can forge it). Production callers should use
// ListenForTask instead, which binds the task id by closure.
func (g *Gateway) Listen(ctx context.Context, addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	g.listener = ln
	g.server = &http.Server{
		Handler: http.HandlerFunc(g.handle),
		// Tight timeouts: a sandbox should not hold a proxy idle for long.
		// ReadHeaderTimeout bounds the headers; ReadTimeout bounds the whole
		// request (incl. body) so a slow-body attacker can't pin a goroutine.
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	g.mu.Unlock()
	go g.server.Serve(ln)
	return ln.Addr().String(), nil
}

// taskListener is a per-task egress listener. Its handler binds the task id
// by closure, so attribution comes from which listener the traffic arrived on
// (a host-side, unforgeable fact) rather than any guest-supplied identifier.
// Closing it stops that task's proxy without affecting other tasks.
type taskListener struct {
	taskID   string
	addr     string
	server   *http.Server
	listener net.Listener
	gateway  *Gateway
}

// Addr returns the host:port clients should dial.
func (t *taskListener) Addr() string { return t.addr }

// Close stops the per-task listener.
func (t *taskListener) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return t.server.Shutdown(ctx)
}

// ListenForTask opens a DEDICATED listener for one task. Traffic arriving on
// the returned listener is attributed to taskID by construction — the guest
// is handed this listener's host:port as its proxy and dials ONLY it, so the
// task id is fixed at the network layer and cannot be forged by the guest
// (unlike the X-Task-Id header on the shared listener). The guest never sees
// the task id string. The listener is owned by the caller, which must Close
// it when the task exits.
func (g *Gateway) ListenForTask(ctx context.Context, taskID string) (*taskListener, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	addr := "127.0.0.1:0"
	if deadline, ok := ctx.Deadline(); ok {
		_ = deadline // currently informational; the listener has no dial timeout
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tl := &taskListener{
		taskID:   taskID,
		addr:     ln.Addr().String(),
		listener: ln,
		gateway:  g,
	}
	// Bound the task to this listener so the handler resolves the policy even
	// before any request arrives (and so ListenForTask is self-contained).
	if g.policy(taskID) == nil {
		g.SetPolicy(taskID, &Policy{})
	}
	tl.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Authoritative attribution: the task id is bound by closure to
			// this listener, so we overwrite any guest-supplied X-Task-Id.
			r.Header.Set("X-Task-Id", taskID)
			g.handle(w, r)
		}),
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go tl.server.Serve(ln)
	return tl, nil
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
// Known limitation: the tunnel relays opaque TLS bytes, so EgressInject
// credentials can never be attached to tunneled requests — an Inject rule
// matches the tunnel only at the host level (see ApplyInject).
func (g *Gateway) handleConnect(w http.ResponseWriter, r *http.Request, task string, pol *Policy) {
	v := viewFromConnect(r)
	d := g.decideDomain(v, pol)
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
	// Tests tunnelling to loopback targets bypass via the same test-only
	// flag as handleHTTP (EnableSSRFBypassForTest).
	if g.ssrFloorEnabled() && isPrivate(targetConn.RemoteAddr()) {
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
	g.record(task, r, DecisionAllow, "CONNECT "+v.host)
	go pipe(clientConn, targetConn, task, g, pol)
	go pipe(targetConn, clientConn, task, g, pol)
}

// handleHTTP handles plain HTTP requests (body visible, method/size enforced).
// It applies the SAME SSRF IP-floor check as handleConnect (via a custom
// DialContext) so a domain that resolves to an internal IP is refused here
// too — not only on CONNECT.
func (g *Gateway) handleHTTP(w http.ResponseWriter, r *http.Request, task string, pol *Policy) {
	v := viewFromHTTP(r)
	d := g.decideDomain(v, pol)
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
	// Size cap on request body. r.ContentLength is -1 for chunked transfers,
	// so also wrap r.Body in a LimitReader: a chunked sender can't bypass the
	// cap by omitting Content-Length.
	var bodyReader io.Reader = r.Body
	if pol.MaxRequestBody > 0 {
		if r.ContentLength > pol.MaxRequestBody {
			g.record(task, r, DecisionBlock, fmt.Sprintf("request body %d > %d", r.ContentLength, pol.MaxRequestBody))
			http.Error(w, "egress: request too large", http.StatusRequestEntityTooLarge)
			return
		}
		bodyReader = &io.LimitedReader{R: r.Body, N: pol.MaxRequestBody + 1}
	}
	// Forward the SAME path the policy view evaluated (viewFromHTTP /
	// normalizePath): whatever cleaning the policy saw, the upstream must
	// receive too — the proxy must not forward a raw "//a/../b" that the
	// policy judged as "/b". RawQuery is preserved; empty path forwards as
	// root ("/").
	outURL := *r.URL
	outURL.Path = normalizePath(outURL.Path)
	outURL.RawPath = "" // re-encode from the normalized Path
	outReq, err := http.NewRequest(r.Method, outURL.String(), bodyReader)
	if err != nil {
		http.Error(w, "egress: bad request", http.StatusBadRequest)
		return
	}
	// Strip internal + hop-by-hop headers before forwarding. X-Task-Id is an
	// internal routing/audit identifier and must not leak to third parties;
	// hop-by-hop headers per RFC 7230 §6.1 are connection-scoped.
	outReq.Header = stripInternalHeaders(r.Header.Clone())
	// Credential injection: if the first fully matching allow rule carries
	// Inject, add the header.
	g.ApplyInject(outReq, v, pol)
	// SSRF floor: dial through a custom transport whose DialContext rejects
	// any IP that resolves to a private/loopback/link-local range. This mirrors
	// the isPrivate() check on handleConnect's established connection. Tests
	// that need to hit a loopback upstream bypass it via EnableSSRFBypassForTest.
	transport := g.dialCheckedTransport()
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		reason := "upstream error: " + err.Error()
		if isSSRFDialError(err) {
			reason = "target resolved to private IP (SSRF floor)"
		}
		g.record(task, r, DecisionBlock, reason)
		code := http.StatusBadGateway
		if isSSRFDialError(err) {
			code = http.StatusForbidden
		}
		http.Error(w, "egress: "+reason, code)
		return
	}
	defer resp.Body.Close()
	// Detect if the client exceeded the request-body cap; if so, we cannot
	// trust the upstream's response and abort with 413 instead.
	if pol.MaxRequestBody > 0 {
		if lr, ok := bodyReader.(*io.LimitedReader); ok && lr.N <= 0 {
			g.record(task, r, DecisionBlock, "chunked request body exceeded cap")
			http.Error(w, "egress: request too large", http.StatusRequestEntityTooLarge)
			return
		}
	}
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
	g.record(task, r, DecisionAllow, fmt.Sprintf("%s %s -> %d (%dB)", r.Method, v.host, resp.StatusCode, n))
}

// dialCheckedTransport returns an http.RoundTripper whose DialContext rejects
// private/loopback/link-local destination IPs. When g.ssrfBypass is set (test
// only), the DialContext is the standard one so loopback upstreams work.
//
// Every transport constructed here disables keep-alives: handleHTTP creates a
// fresh transport PER request (so it can scope DialContext to that request's
// SSRF check), and a transport that is discarded while holding idle connections
// leaks them (and their goroutines) until GC. DisableKeepAlives=true makes each
// round-trip open+close its own connection, so discarding the transport has no
// dangling state.
func (g *Gateway) dialCheckedTransport() *http.Transport {
	g.mu.RLock()
	bypass := g.ssrfBypass
	g.mu.RUnlock()
	if bypass {
		return &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
			DisableKeepAlives:     true,
			IdleConnTimeout:       1 * time.Second,
		}
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if isPrivate(conn.RemoteAddr()) {
				conn.Close()
				return nil, errPrivateIPBlocked
			}
			return conn, nil
		},
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     true,
		IdleConnTimeout:       1 * time.Second,
	}
}

// errPrivateIPBlocked is returned by dialCheckedTransport when the dial lands
// on a private/loopback/link-local IP. isSSRFDialError recognizes it.
var errPrivateIPBlocked = errors.New("egress: dialed address is private/loopback")

// isSSRFDialError reports whether err is the SSRF-floor rejection.
func isSSRFDialError(err error) bool { return errors.Is(err, errPrivateIPBlocked) }

// hopByHopHeaders are connection-scoped headers per RFC 7230 §6.1 that must
// not be forwarded by a proxy.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// stripInternalHeaders returns a copy of hdr with X-Task-Id and all
// hop-by-hop headers removed. The clone is defensive so we never mutate the
// inbound request's header map.
func stripInternalHeaders(hdr http.Header) http.Header {
	out := hdr.Clone()
	out.Del("X-Task-Id")
	for _, h := range hopByHopHeaders {
		out.Del(h)
	}
	return out
}

// requestView is the policy-relevant view of an outbound request, shared by
// decideDomain and ApplyInject so both walk the Rules with the same
// first-match-wins semantics.
type requestView struct {
	method string
	host   string // lowercase, port-stripped
	path   string // "" when not visible (CONNECT tunnels)
	scheme string // "http" | "https"
	port   string // effective port as a string
}

// viewFromHTTP builds the view for a plain HTTP proxy request. The path is
// normalized by normalizePath — the same function handleHTTP uses to build
// the forwarded URL — so the policy view and the upstream always see the
// same resource; an empty path means root.
func viewFromHTTP(r *http.Request) requestView {
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host, urlPort := splitHostPort(r.Host)
	port := urlPort
	if port == "" {
		if strings.EqualFold(scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return requestView{
		method: r.Method,
		host:   strings.ToLower(host),
		path:   normalizePath(r.URL.Path),
		scheme: strings.ToLower(scheme),
		port:   port,
	}
}

// normalizePath canonicalizes a request path for BOTH the policy view
// (viewFromHTTP) and the forwarded request (handleHTTP), so the gateway can
// never allow one path and forward another ("//a/../b" and "/b" are one
// resource). Dot segments and duplicate slashes are removed, but the
// ORIGINAL trailing slash is preserved: "/v1/" and "/v1" are distinct
// resources (RFC 3986 §6.2.3), and collapsing them would change what the
// upstream receives. An empty path means root ("/").
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	clean := path.Clean(p)
	// path.Clean drops a trailing slash; re-attach it when the caller sent
	// one — unless Clean collapsed the path all the way to the root, which
	// keeps its single slash (never "//").
	if clean != "/" && strings.HasSuffix(p, "/") {
		clean += "/"
	}
	return clean
}

// viewFromConnect builds the (partial) view for a CONNECT tunnel: the target
// host and port are visible, the path is encrypted.
func viewFromConnect(r *http.Request) requestView {
	host, port := splitHostPort(r.Host)
	if port == "" {
		port = "443"
	}
	return requestView{
		method: http.MethodConnect,
		host:   strings.ToLower(host),
		scheme: "https",
		port:   port,
	}
}

// ruleMatches reports whether every constraint present on the rule matches
// the request view. A rule with neither Host nor SNI never matches; unset
// constraints (Method/Path/Scheme/Port) are wildcards.
func ruleMatches(r EgressRule, v requestView) bool {
	h := r.Host
	if h == "" {
		h = r.SNI
	}
	if h == "" || !domainMatches(v.host, strings.ToLower(h)) {
		return false
	}
	if len(r.Method) > 0 {
		ok := false
		for _, m := range r.Method {
			if strings.EqualFold(m, v.method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if r.Path != "" && !pathMatches(r.Path, v.path) {
		return false
	}
	if r.Scheme != "" && !strings.EqualFold(r.Scheme, v.scheme) {
		return false
	}
	if r.Port != 0 && strconv.Itoa(r.Port) != v.port {
		return false
	}
	return true
}

// pathMatches supports exact paths and "/prefix/*" globs (per EgressRule.Path).
// A glob also matches the bare prefix directory ("/v1/*" matches "/v1").
func pathMatches(rule, p string) bool {
	if rule == p {
		return true
	}
	if strings.HasSuffix(rule, "/*") {
		prefix := strings.TrimSuffix(rule, "*") // "/v1/"
		bare := strings.TrimSuffix(prefix, "/") // "/v1"
		return strings.HasPrefix(p, prefix) || p == bare
	}
	return false
}

// decideDomain evaluates the flat BlockDomains denylist FIRST — an
// explicitly blocked domain must never be rescued by a rule — then applies
// the Rules with first-match-wins semantics: only a rule that fully matches
// (host/SNI plus method, path, scheme, port) may decide. When Policy.Rules is
// empty the flat allow list is the fallback.
func (g *Gateway) decideDomain(v requestView, pol *Policy) Decision {
	for _, b := range pol.BlockDomains {
		if domainMatches(v.host, strings.ToLower(b)) {
			return DecisionBlock
		}
	}
	if len(pol.Rules) > 0 {
		for _, r := range pol.Rules {
			if !ruleMatches(r, v) {
				continue
			}
			if r.Allow != nil && !*r.Allow {
				return DecisionBlock
			}
			return DecisionAllow
		}
		return DecisionBlock // no rule fully matched -> deny
	}
	for _, a := range pol.AllowDomains {
		if domainMatches(v.host, strings.ToLower(a)) {
			return DecisionAllow
		}
	}
	return DecisionBlock // default deny
}

// ApplyInject adds credential headers from the FIRST fully matching rule.
// Credentials are injected ONLY when the request travels over HTTPS
// (v.scheme == "https"): writing a secret onto a plaintext HTTP request
// would leak it to every hop on the wire, so even a rule with no Scheme
// constraint of its own must not inject over http. Call after decideDomain
// returned Allow; it mutates outReq.Header in place. A rule that matches but
// carries no Inject stops the walk: a later, broader rule must never leak
// its credentials into this request.
//
// Limitation (by construction): CONNECT tunnels never receive injections.
// handleConnect relays opaque TLS bytes with no readable header, so an
// Inject rule may authorize a CONNECT tunnel (via its host) but can NEVER
// deliver its secret through it — credentials for tunneled HTTPS must be
// provisioned inside the guest, not at the proxy.
func (g *Gateway) ApplyInject(outReq *http.Request, v requestView, pol *Policy) {
	if len(pol.Rules) == 0 {
		return
	}
	if !strings.EqualFold(v.scheme, "https") {
		return // plaintext request: never attach credentials
	}
	for _, r := range pol.Rules {
		if !ruleMatches(r, v) {
			continue
		}
		if r.Inject != nil && r.Inject.Header != "" && r.Inject.Secret != "" && (r.Allow == nil || *r.Allow) {
			format := r.Inject.Format
			if format == "" {
				format = "${SECRET}"
			}
			val := strings.ReplaceAll(format, "${SECRET}", r.Inject.Secret)
			outReq.Header.Set(r.Inject.Header, val)
		}
		return // first fully matching rule wins, like CubeEgress
	}
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

// ssrFloorEnabled reports whether the SSRF IP-floor is active (false only
// when the test-only bypass flag is set — see EnableSSRFBypassForTest).
func (g *Gateway) ssrFloorEnabled() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return !g.ssrfBypass
}

func (g *Gateway) policy(task string) *Policy {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.policies[task]
}

func (g *Gateway) record(task string, r *http.Request, d Decision, reason string) {
	// Pick the task-specific ledger when one is registered, falling back to
	// the gateway-wide ledger. This keeps multi-task traffic attributed to
	// the right task instead of the controller's default.
	l := g.ledger
	g.mu.RLock()
	if tl, ok := g.ledgers[task]; ok && tl != nil {
		l = tl
	}
	g.mu.RUnlock()
	if l == nil {
		return
	}
	if err := l.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  r.RemoteAddr,
		Action:   r.Method + " " + stripPort(r.Host),
		Params:   map[string]interface{}{"task": task, "bytes": r.ContentLength},
		Decision: audit.Decision(d.String()),
		Reason:   reason,
	}); err != nil {
		// Don't swallow: a missing audit row for an allow/block decision is a
		// real integrity gap and should be visible to operators.
		log.Printf("egress: audit append failed for task %s: %v", task, err)
	}
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

// splitHostPort extracts host and port from an authority string, handling
// bracketed IPv6 literals ("[::1]:8443") and bare hosts. When no port is
// present the host is returned whole and port is "".
func splitHostPort(hostport string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	// No parseable port. A bracketed IPv6 literal ([::1]) keeps its brackets
	// through URL parsing; strip them so the host compares equal to rules.
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return hostport[1 : len(hostport)-1], ""
	}
	return hostport, ""
}

// stripPort strips the port from an authority for logging (DIP-lite).
func stripPort(hostport string) string {
	h, _ := splitHostPort(hostport)
	return h
}

var _ = bufio.NewReader // keep import for future streaming body scan
var _ = errors.New
var _ = log.Print
