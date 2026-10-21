package network

// ingress.go — host-side L7 front for inbound port mappings that declare a
// traffic access token and/or a request-host mask (portmap.go). A plain
// mapping is a bare iptables DNAT straight into the guest; these mappings
// instead terminate the HTTP connection at the host so the token can be
// checked and the Host header rewritten before the request is forwarded.
//
//	Listen HostPort
//	  └─ token check (X-Access-Token header or ?access_token= query)
//	     └─ rewrite Host -> mask_request_host
//	        └─ reverse-proxy -> guest GuestIP:GuestPort
//
// The proxy runs in-process for the lifetime of the mapping: AddPortMapping
// starts it, DeletePortMapping / CleanupTaskPortMappings stop it. Like the
// iptables rules it replaces, running proxies are not replayed across a
// host restart — mappings are re-registered by the task spec on next launch.

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// ingressHeaderToken is the header a client presents the token in; the
// ?access_token= query parameter is accepted as an alternate.
const ingressHeaderToken = "X-Access-Token"

// ingressProxy is one running L7 front.
type ingressProxy struct {
	taskID      string
	hostPort    int
	target      *url.URL
	accessToken string
	maskHost    string
	ln          net.Listener
	srv         *http.Server
}

var (
	ingressMu      sync.Mutex
	ingressProxies = map[string]*ingressProxy{} // key: ingestKey(taskID, hostPort)
)

// ingressKey identifies a task's ingress proxy by task ID and host port.
func ingressKey(taskID string, hostPort int) string {
	return taskID + "/" + strconv.Itoa(hostPort)
}

// authorized accepts any request if no token is configured; otherwise it
// checks X-Access-Token, falling back to ?access_token= when the header is empty.
// The comparison is constant-time so a timing side channel cannot recover
// the token byte by byte.
func (p *ingressProxy) authorized(r *http.Request) bool {
	if p.accessToken == "" {
		return true
	}
	got := r.Header.Get(ingressHeaderToken)
	if got == "" {
		got = r.URL.Query().Get("access_token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(p.accessToken)) == 1
}

// startIngressProxy binds HostPort and serves the token/Host-masking
// reverse proxy on all interfaces. Target URL and listener bind errors are
// returned; upstream forwarding failures become HTTP 502 responses. Callers must hold
// no other ingress lock.
func startIngressProxy(m PortMapping) error {
	target, err := url.Parse("http://" + net.JoinHostPort(m.GuestIP, strconv.Itoa(m.GuestPort)))
	if err != nil {
		return fmt.Errorf("network: ingress target: %w", err)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", m.HostPort))
	if err != nil {
		return fmt.Errorf("network: ingress listen on %d: %w", m.HostPort, err)
	}
	p := &ingressProxy{
		taskID:      m.TaskID,
		hostPort:    m.HostPort,
		target:      target,
		accessToken: m.AccessToken,
		maskHost:    m.MaskRequestHost,
		ln:          ln,
	}
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			if p.maskHost != "" {
				req.Host = p.maskHost
				req.Header.Set("Host", p.maskHost)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	p.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !p.authorized(r) {
				w.Header().Set("WWW-Authenticate", "Access-Token")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		if serr := p.srv.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			log.Printf("network: ingress proxy %s stopped: %v", ingressKey(p.taskID, p.hostPort), serr)
		}
	}()
	ingressMu.Lock()
	ingressProxies[ingressKey(p.taskID, p.hostPort)] = p
	ingressMu.Unlock()
	return nil
}

// stopIngressProxy shuts one running proxy down; a missing proxy is a
// no-op.
func stopIngressProxy(taskID string, hostPort int) {
	ingressMu.Lock()
	p := ingressProxies[ingressKey(taskID, hostPort)]
	delete(ingressProxies, ingressKey(taskID, hostPort))
	ingressMu.Unlock()
	if p != nil {
		_ = p.srv.Close()
	}
}

// stopTaskIngressProxies shuts every proxy belonging to one task.
func stopTaskIngressProxies(taskID string) {
	ingressMu.Lock()
	var victims []*ingressProxy
	for k, p := range ingressProxies {
		if p.taskID == taskID {
			victims = append(victims, p)
			delete(ingressProxies, k)
		}
	}
	ingressMu.Unlock()
	for _, p := range victims {
		_ = p.srv.Close()
	}
}
