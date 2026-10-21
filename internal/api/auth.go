package api

// auth.go — multi-key authentication + optional auth-callback delegation.
//
// Model:
//   - API_SECRET stays the required bootstrap master key (operator
//     "master"): removing it would break every existing deployment.
//   - PVM_API_KEYS / PVM_API_KEYS_FILE add named keys with an operator
//     (and optional tenant) label. Entries look like:
//       key
//       key:operator
//       key:operator:tenant
//     separated by commas or newlines; '#' starts a comment line in the
//     file form. Named keys are how a multi-operator single-host
//     deployment separates audit actors without a control plane.
//   - PVM_AUTH_CALLBACK_URL delegates unknown keys to an external
//     authenticator (the deployment's own identity provider). Semantics
//     are fail-closed: HTTP 200 allows, any other callback status denies
//     with 401, and an unreachable/erroring callback fails CLOSED with
//     500 — a broken IdP must never open the door. The callback receives
//     the RAW key, so a non-https non-loopback URL is refused at load
//     time (delegation disabled, unknown keys stay 401) unless the
//     private-network escape hatch PVM_AUTH_CALLBACK_ALLOW_HTTP=1 is
//     set explicitly — and even then the callback host must resolve
//     into loopback/RFC1918/ULA space (public cleartext stays refused);
//     redirects are never followed (the key must not be replayed to
//     another location) and concurrent callbacks are capped.
//
// Both ecosystem header conventions are accepted everywhere:
// Authorization: Bearer <key> (preferred) and X-API-KEY <key>.
// Comparison is constant-time per candidate.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// Auth errors surfaced by Authenticate; the middleware maps them to 401
// (denied) and 500 (authenticator unavailable) respectively.
var (
	ErrAuthDenied      = errors.New("auth: unknown or rejected API key")
	ErrAuthUnavailable = errors.New("auth: auth callback unavailable (fail-closed)")
)

// APIKey is one named credential.
type APIKey struct {
	Key      string
	Operator string
	Tenant   string
	// IsApprover marks a key listed in PVM_APPROVER_KEYS: it is authorized
	// to create and decide approval tickets even when the approval plane is
	// separated from the execution plane (strong mode). Regular keys stay
	// auditable actors but lose approval authority once approver keys exist.
	IsApprover bool
}

// Callback POST budget: the raw key rides in the body, so the exchange
// is capped in time (client timeout), never redirected (CheckRedirect),
// and capped in concurrency (a junk-key flood must not pile up one
// 5-second outbound request per API request on the process and the IdP).
const (
	callbackTimeout     = 5 * time.Second
	callbackConcurrency = 8
)

// KeyRegistry holds the locally known keys plus the optional callback.
type KeyRegistry struct {
	keys     []APIKey
	callback string
	// callbackCleartext marks a callback whose URL survived the
	// PVM_AUTH_CALLBACK_ALLOW_HTTP=1 private-network opt-in. Every dial is
	// re-checked against the private-net floor at connect time so a DNS
	// rebinding between the load-time validation and the POST cannot ship
	// the raw key to a public listener.
	callbackCleartext bool
	client            *http.Client
	cbSem             chan struct{}
	// approverKeys is the optional PVM_APPROVER_KEYS set. When non-empty,
	// the approval endpoints require one of these keys (trust separation
	// between the execution plane and the human approval plane).
	approverKeys []string
}

// LoadKeyRegistry builds the registry from the environment. The master
// key comes from API_SECRET (caller has already enforced its presence);
// named keys come from PVM_API_KEYS and PVM_API_KEYS_FILE. Approver keys come
// from PVM_APPROVER_KEYS. An unreadable key file leaves its keys unloaded;
// the rest of the registry remains usable.
func LoadKeyRegistry() *KeyRegistry {
	r := &KeyRegistry{
		callback: strings.TrimSpace(os.Getenv("PVM_AUTH_CALLBACK_URL")),
		cbSem:    make(chan struct{}, callbackConcurrency),
	}
	if master := os.Getenv("API_SECRET"); master != "" {
		r.keys = append(r.keys, APIKey{Key: master, Operator: "master"})
	}
	for _, entry := range parseKeyEntries(os.Getenv("PVM_API_KEYS")) {
		r.keys = append(r.keys, entry)
	}
	if path := strings.TrimSpace(os.Getenv("PVM_API_KEYS_FILE")); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			// NOT silently skippable: a typo'd path would silently drop a
			// whole operator's keys with no trace. Fail loudly at startup;
			// the keys themselves stay unloaded (fail-closed).
			log.Printf("auth: PVM_API_KEYS_FILE %q unreadable, its keys are NOT loaded: %v", path, err)
		} else {
			for _, line := range strings.Split(string(data), "\n") {
				for _, entry := range parseKeyEntries(line) {
					r.keys = append(r.keys, entry)
				}
			}
		}
	}
	// Approval-plane trust separation (PVM_APPROVER_KEYS): when set, only
	// these keys may create/decide approval tickets — SDK/agent keys that
	// triggered an approval_required intercept can no longer self-approve
	// the same gate. Keys are raw secrets (no operator annotation).
	for _, entry := range parseKeyEntries(os.Getenv("PVM_APPROVER_KEYS")) {
		if entry.Key != "" {
			r.approverKeys = append(r.approverKeys, entry.Key)
		}
	}
	if len(r.approverKeys) > 0 {
		for i := range r.keys {
			for _, ak := range r.approverKeys {
				if subtle.ConstantTimeCompare([]byte(r.keys[i].Key), []byte(ak)) == 1 {
					r.keys[i].IsApprover = true
					break
				}
			}
		}
	}
	r.callback = secureCallback(r.callback)
	// Cleartext callbacks (the ALLOW_HTTP private-net opt-in) get a dialing
	// transport that re-verifies the private-net floor on every connect —
	// the load-time hostPrivatenetOnly check alone is TOCTOU-vulnerable to
	// rebinding between validation and use.
	r.callbackCleartext = r.callback != "" && !strings.HasPrefix(r.callback, "https://")
	r.client = newCallbackClient(r.callbackCleartext)
	return r
}

// newCallbackClient builds the hardened exchange for callback POSTs:
// bounded in time and never redirected — the body carries the RAW API
// key, so a 307/308 (or any 3xx the client would upgrade) must never
// replay it to another location. When privateOnly is set (cleartext
// callback opt-in), every dial is re-checked: the connection must land
// on a loopback/RFC1918/ULA address or it is aborted before a single
// byte of the key-bearing body leaves the process.
func newCallbackClient(privateOnly bool) *http.Client {
	transport := &http.Transport{
		// Defaults comparable to http.DefaultTransport, minus proxy env
		// trust: the callback destination is configuration, not something
		// an ambient HTTP_PROXY should be able to hijack.
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: callbackTimeout}).DialContext,
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: callbackTimeout,
	}
	if privateOnly {
		base := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := base(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if ta, ok := c.RemoteAddr().(*net.TCPAddr); !ok || ta.IP == nil ||
				!(ta.IP.IsLoopback() || ta.IP.IsPrivate()) {
				_ = c.Close()
				return nil, fmt.Errorf("auth: callback dial to %s landed on non-private %v — rebinding guard (fail-closed)", addr, c.RemoteAddr())
			}
			return c, nil
		}
	}
	return &http.Client{
		Timeout: callbackTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// secureCallback enforces the cleartext rule for the callback URL:
// Authenticate POSTs the RAW key there, so anything other than https (or
// a loopback/local authenticator) is refused — delegation is disabled and
// unknown keys keep answering 401 instead of shipping secrets on the
// wire. Explicit opt-in for private-network TLS-less deployments:
// PVM_AUTH_CALLBACK_ALLOW_HTTP=1 — and even then the target must resolve
// into loopback/RFC1918/ULA space (hostPrivatenetOnly); public cleartext
// is never allowed.
// lookupHost is net.LookupHost indirected for tests (the "localhost"
// verification below must be testable against a hostile resolver).
var lookupHost = net.LookupHost

func secureCallback(callback string) string {
	if callback == "" {
		return ""
	}
	u, err := url.Parse(callback)
	if err != nil {
		log.Printf("auth: PVM_AUTH_CALLBACK_URL %q is not a valid URL "+
			"(callback delegation disabled, auth stays fail-closed): %v", callback, err)
		return ""
	}
	if u.Scheme == "https" {
		return callback
	}
	if host := u.Hostname(); host != "" {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return callback
		}
		// "localhost" is only a name: /etc/hosts or a resolver can point
		// it anywhere. Accept it only when EVERY resolved address is
		// loopback; anything else is treated like any other remote host.
		if host == "localhost" && localhostResolvesLoopbackOnly() {
			return callback
		}
	}
	if os.Getenv("PVM_AUTH_CALLBACK_ALLOW_HTTP") == "1" {
		// The opt-in is pinned to private networks: a cleartext callback
		// to a public address stays fail-closed no matter what.
		if !hostPrivatenetOnly(u.Hostname()) {
			log.Printf("auth: PVM_AUTH_CALLBACK_URL %q is cleartext http to a "+
				"NON-private address — callback delegation DISABLED even with "+
				"PVM_AUTH_CALLBACK_ALLOW_HTTP=1 (raw keys must not cross the "+
				"public internet in the clear)", callback)
			return ""
		}
		log.Printf("auth: PVM_AUTH_CALLBACK_ALLOW_HTTP=1: raw API keys will be "+
			"sent over %s to %q (private-network TLS-less deployment)", u.Scheme, callback)
		return callback
	}
	log.Printf("auth: PVM_AUTH_CALLBACK_URL %q is not https and not loopback — "+
		"callback delegation DISABLED (fail-closed 401s); set "+
		"PVM_AUTH_CALLBACK_ALLOW_HTTP=1 to explicitly allow cleartext keys", callback)
	return ""
}

// localhostResolvesLoopbackOnly reports whether every address the host
// resolver returns for "localhost" is a loopback address. A resolution
// failure is treated as "not verifiable" (fail closed).
func localhostResolvesLoopbackOnly() bool {
	ips, err := lookupHost("localhost")
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		pip := net.ParseIP(ip)
		if pip == nil || !pip.IsLoopback() {
			return false
		}
	}
	return true
}

// hostPrivatenetOnly reports whether every address `host` resolves to (or
// literally is) is loopback or RFC1918/ULA private space. It bounds the
// PVM_AUTH_CALLBACK_ALLOW_HTTP escape hatch to genuinely private
// networks: cleartext RAW keys to a PUBLIC address stay fail-closed even
// with the opt-in. Resolution failure or an empty answer set fails
// closed (mirroring localhostResolvesLoopbackOnly).
func hostPrivatenetOnly(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	ips, err := lookupHost(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		pip := net.ParseIP(ip)
		if pip == nil || (!pip.IsLoopback() && !pip.IsPrivate()) {
			return false
		}
	}
	return true
}

// parseKeyEntries splits one blob (env value or file line) into keys.
// Empty segments and whole-line '#' comments are ignored; more than three
// fields is a malformed entry and skipped (never half-loaded). An entry
// containing inner whitespace or '#' (e.g. "key # note") cannot be a key
// the caller meant — it is skipped with a log line instead of being
// silently loaded AS the key (the historical behavior loaded garbage
// that then never matched any request).
func parseKeyEntries(blob string) []APIKey {
	var out []APIKey
	blob = strings.TrimSpace(blob)
	if blob == "" || strings.HasPrefix(blob, "#") {
		return nil
	}
	for _, raw := range strings.FieldsFunc(blob, func(r rune) bool { return r == ',' || r == '\n' }) {
		raw = strings.TrimSpace(raw)
		// Inner whitespace/'#' cannot be part of a key (list separators
		// were already handled); anything left is a malformed entry.
		if strings.ContainsAny(raw, " \t#") {
			log.Printf("auth: skipping malformed key entry %q (inline spaces or '#' "+
				"are not supported; put comments on their own line)", raw)
			continue
		}
		parts := strings.Split(raw, ":")
		if len(parts) == 0 || parts[0] == "" || len(parts) > 3 {
			continue
		}
		k := APIKey{Key: parts[0], Operator: parts[0]}
		if len(parts) >= 2 && parts[1] != "" {
			k.Operator = parts[1]
		}
		if len(parts) == 3 {
			k.Tenant = parts[2]
		}
		out = append(out, k)
	}
	return out
}

// Lookup resolves key against the local set. Constant-time per candidate;
// the candidate count is tiny and not secret.
func (r *KeyRegistry) Lookup(key string) (APIKey, bool) {
	for _, k := range r.keys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(k.Key)) == 1 {
			return k, true
		}
	}
	// A raw PVM_APPROVER_KEYS entry that was not ALSO loaded as a regular
	// key still authenticates (operator name falls back to "approver"),
	// so an approver-only key can call the API without being the master.
	for _, ak := range r.approverKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(ak)) == 1 {
			return APIKey{Key: key, Operator: "approver", IsApprover: true}, true
		}
	}
	return APIKey{}, false
}

// HasApproverKeys reports whether the approval plane is running in strong
// (trust-separated) mode: PVM_APPROVER_KEYS was configured and every
// approval create/decide must present one of those keys.
func (r *KeyRegistry) HasApproverKeys() bool {
	return len(r.approverKeys) > 0
}

// callbackRequest is the JSON body posted to the auth callback.
type callbackRequest struct {
	Key    string `json:"key"`
	Path   string `json:"path"`
	Method string `json:"method"`
}

// Authenticate resolves key to an identity. path/method are forwarded to
// the callback so it can make route-scoped decisions for keys not found locally.
// Only HTTP 200 accepts a callback identity. Missing callbacks or other status
// codes yield ErrAuthDenied; callback capacity, encoding, or request failures
// yield or wrap ErrAuthUnavailable.
func (r *KeyRegistry) Authenticate(key, path, method string) (APIKey, error) {
	if k, ok := r.Lookup(key); ok {
		return k, nil
	}
	if r.callback == "" {
		return APIKey{}, ErrAuthDenied
	}
	client := r.client
	if client == nil {
		client = newCallbackClient(r.callbackCleartext)
	}
	// Cap in-flight callbacks (junk keys are free to send; the IdP is
	// not). A saturated cap fails closed like an unreachable IdP.
	if r.cbSem != nil {
		select {
		case r.cbSem <- struct{}{}:
			defer func() { <-r.cbSem }()
		default:
			return APIKey{}, fmt.Errorf("%w: callback concurrency cap reached", ErrAuthUnavailable)
		}
	}
	body, err := json.Marshal(callbackRequest{Key: key, Path: path, Method: method})
	if err != nil {
		return APIKey{}, ErrAuthUnavailable
	}
	resp, err := client.Post(r.callback, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return APIKey{}, fmt.Errorf("%w: %v", ErrAuthUnavailable, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK {
		op := resp.Header.Get("X-PVM-Actor")
		if op == "" {
			op = "callback"
		}
		return APIKey{Key: key, Operator: op}, nil
	}
	return APIKey{}, ErrAuthDenied
}

// HasCallback reports whether callback delegation is configured (used to
// decide 401 vs 500 on misses).
func (r *KeyRegistry) HasCallback() bool { return r.callback != "" }

// requestKey extracts the credential using both ecosystem conventions;
// Bearer wins when both are present. The scheme prefix requires its
// separator ("Bearer "): a header like "Bearerxyz" is a bare credential,
// not a Bearer form, and must stay whole so it simply fails to match.
func requestKey(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if v := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")); v != auth {
			return strings.TrimSpace(v)
		}
		return strings.TrimSpace(auth)
	}
	return r.Header.Get("X-API-KEY")
}

// authError writes the fail-closed distinction: a configured but broken
// callback surfaces as 500, a plain rejection as 401. The underlying
// unavailable-error names the callback URL and transport details, so it
// is logged server-side only — unauthenticated clients get a fixed body.
func authError(c echo.Context, err error) error {
	if errors.Is(err, ErrAuthUnavailable) {
		log.Printf("auth: %v", err)
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"message": "authentication backend unavailable"})
	}
	return c.JSON(http.StatusUnauthorized, map[string]string{"message": "unauthenticated"})
}

// keyAuthMiddleware is the /api-group guard: Bearer or X-API-KEY, local
// keys first, then callback delegation (fail-closed). On success the
// actor (and tenant, when present) land in the echo context for audit
// attribution.
func keyAuthMiddleware(reg *KeyRegistry) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := requestKey(c.Request())
			if key == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "unauthenticated"})
			}
			id, err := reg.Authenticate(key, c.Request().URL.Path, c.Request().Method)
			if err != nil {
				return authError(c, err)
			}
			c.Set("actor", id.Operator)
			c.Set("is_approver", id.IsApprover)
			// Key fingerprint (never the raw key) for same-key comparisons
			// on the approval plane.
			sum := sha256.Sum256([]byte(key))
			c.Set("key_fp", hex.EncodeToString(sum[:]))
			if id.Tenant != "" {
				c.Set("tenant", id.Tenant)
			}
			return next(c)
		}
	}
}
