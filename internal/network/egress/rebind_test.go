package egress

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// staticChecker is a fixed LearnedIPChecker for rebinding-guard tests.
type staticChecker struct {
	ips map[string][]net.IP // "task\x00host" -> learned IPs
}

func (c staticChecker) LearnedIPs(task, host string) []net.IP {
	return c.ips[task+"\x00"+host]
}

// proxyGet issues one GET through the gateway and returns the status.
func proxyGet(t *testing.T, g *Gateway, target, task string) int {
	t.Helper()
	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://" + g.Addr())
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("X-Task-Id", task)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestRebindingGuard_HTTP pins the P1-B learned-IP dial check: when a host
// was DNS-learned for the task, a dial landing OUTSIDE the learned set is
// rejected (403); a dial landing inside it passes; and the guard toggles
// off cleanly.
func TestRebindingGuard_HTTP(t *testing.T) {
	be := echoBackend(t)
	hostport := strings.TrimPrefix(be.URL, "http://")
	host := stripPort(hostport) // 127.0.0.1
	pol := &Policy{AllowDomains: []string{host}}
	g := startGateway(t, pol)

	backendIP := net.ParseIP(host)
	stranger := net.ParseIP("203.0.113.9")

	// No checker: guard inert, request flows.
	if got := proxyGet(t, g, be.URL, "t1"); got != 200 {
		t.Fatalf("no checker: status = %d, want 200", got)
	}

	// Checker with the host learned to a DIFFERENT ip: the proxy's own
	// resolution (127.0.0.1) is outside the learned set -> rebind rejected.
	g.SetLearnedChecker(staticChecker{ips: map[string][]net.IP{
		"t1\x00" + host: {stranger},
	}})
	if got := proxyGet(t, g, be.URL, "t1"); got != 403 {
		t.Fatalf("mismatched learned set: status = %d, want 403", got)
	}

	// Learned set containing the dialed ip: allowed.
	g.SetLearnedChecker(staticChecker{ips: map[string][]net.IP{
		"t1\x00" + host: {backendIP, stranger},
	}})
	if got := proxyGet(t, g, be.URL, "t1"); got != 200 {
		t.Fatalf("matching learned set: status = %d, want 200", got)
	}

	// Per-task isolation: another task has NO learned constraint for the
	// same host, so its dial is unchecked.
	g.SetPolicy("t2", pol)
	if got := proxyGet(t, g, be.URL, "t2"); got != 200 {
		t.Fatalf("other task unconstrained: status = %d, want 200", got)
	}

	// Host never learned for t1 (checker returns nothing): fail-open.
	g.SetLearnedChecker(staticChecker{ips: map[string][]net.IP{}})
	if got := proxyGet(t, g, be.URL, "t1"); got != 200 {
		t.Fatalf("unlearned host: status = %d, want 200", got)
	}

	// Flag off: even a mismatching learned set does not block.
	g.SetLearnedChecker(staticChecker{ips: map[string][]net.IP{
		"t1\x00" + host: {stranger},
	}})
	g.SetRebindingGuard(false)
	if got := proxyGet(t, g, be.URL, "t1"); got != 200 {
		t.Fatalf("guard disabled: status = %d, want 200", got)
	}
}

// TestLearnedDialSet covers the guard's inert paths directly.
func TestLearnedDialSet(t *testing.T) {
	g := NewGateway()
	if g.learnedDialSet("t1", "example.com") != nil {
		t.Fatal("nil checker must yield nil set")
	}
	g.SetLearnedChecker(staticChecker{ips: map[string][]net.IP{
		"t1\x00example.com": {net.ParseIP("93.184.216.34")},
	}})
	set := g.learnedDialSet("t1", "example.com")
	if len(set) != 1 {
		t.Fatalf("set = %v, want 1 ip", set)
	}
	if g.learnedDialSet("t1", "") != nil {
		t.Fatal("empty host must yield nil set")
	}
	g.SetRebindingGuard(false)
	if g.learnedDialSet("t1", "example.com") != nil {
		t.Fatal("disabled guard must yield nil set")
	}
}

// TestLearnedSetContainsIP covers non-TCP addrs and membership.
func TestLearnedSetContainsIP(t *testing.T) {
	set := map[string]struct{}{"93.184.216.34": {}}
	if learnedSetContainsIP(set, &net.UDPAddr{IP: net.ParseIP("93.184.216.34")}) {
		t.Fatal("non-TCP addr must not match")
	}
	if !learnedSetContainsIP(set, &net.TCPAddr{IP: net.ParseIP("93.184.216.34")}) {
		t.Fatal("member TCP addr must match")
	}
	if learnedSetContainsIP(set, &net.TCPAddr{IP: net.ParseIP("93.184.216.35")}) {
		t.Fatal("non-member TCP addr must not match")
	}
}
