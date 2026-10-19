package network

// portmap_ingress_test.go — the host-side L7 ingress front for mappings
// that carry a traffic access token and/or a request-host mask
// (ingress.go). These exercise the token gate, Host rewrite and rule shape
// without touching iptables.

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidatePortMappingIngressL7(t *testing.T) {
	bad := []struct {
		name string
		m    PortMapping
	}{
		{"token on udp", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "10.0.0.1", Protocol: "udp", AccessToken: "x"}},
		{"mask on udp", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "10.0.0.1", Protocol: "udp", MaskRequestHost: "h"}},
		{"token too long", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "10.0.0.1", AccessToken: strings.Repeat("a", maxIngressTokenBytes+1)}},
		{"mask too long", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "10.0.0.1", MaskRequestHost: strings.Repeat("a", maxIngressHostBytes+1)}},
		{"mask with slash", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "10.0.0.1", MaskRequestHost: "evil/path"}},
		{"mask with space", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "10.0.0.1", MaskRequestHost: "a b"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePortMapping(tc.m); err == nil {
				t.Fatalf("must be rejected: %+v", tc.m)
			}
		})
	}
	ok := PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "10.0.0.1", AccessToken: "secret", MaskRequestHost: "internal.local"}
	if err := validatePortMapping(ok); err != nil {
		t.Fatalf("valid L7 mapping rejected: %v", err)
	}
}

func TestIngressPortMapRulesNoDNAT(t *testing.T) {
	m := PortMapping{TaskID: "web", HostPort: 8080, GuestPort: 80, GuestIP: "10.0.0.100", AccessToken: "s"}
	on := ingressPortMapRules(m, true)
	off := ingressPortMapRules(m, false)
	if len(on) != 2 || len(off) != 2 {
		t.Fatalf("expected 2 rule sets each, got %d/%d", len(on), len(off))
	}
	for _, argv := range on {
		joined := strings.Join(argv, " ")
		if strings.Contains(joined, "DNAT") {
			t.Fatalf("ingress rule must not DNAT (it would steal the local listener's connections): %v", argv)
		}
		if !strings.Contains(joined, "OUTPUT") && !strings.Contains(joined, "FORWARD") {
			t.Fatalf("unexpected chain: %v", argv)
		}
	}
	// Apply/remove specs must be symmetric.
	norm := func(argv []string, want string) string {
		var rest []string
		for _, tok := range argv {
			if tok == want {
				continue
			}
			rest = append(rest, tok)
		}
		return strings.Join(rest, " ")
	}
	for i := range on {
		if norm(on[i], "-A") != norm(off[i], "-D") {
			t.Fatalf("rule %d drifted:\n%v\n%v", i, on[i], off[i])
		}
	}
}

func TestIngressProxyAuthorized(t *testing.T) {
	open := &ingressProxy{}
	if !open.authorized(httptest.NewRequest(http.MethodGet, "http://example.com/", nil)) {
		t.Fatal("no token configured must not require one")
	}
	p := &ingressProxy{accessToken: "secret"}
	req := func(setup func(*http.Request)) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		setup(r)
		return r
	}
	// Token required: missing and wrong forms.
	if p.authorized(req(func(*http.Request) {})) {
		t.Fatal("missing token must be rejected")
	}
	if p.authorized(req(func(r *http.Request) { r.Header.Set(ingressHeaderToken, "nope") })) {
		t.Fatal("wrong header token must be rejected")
	}
	if !p.authorized(req(func(r *http.Request) { r.Header.Set(ingressHeaderToken, "secret") })) {
		t.Fatal("correct header token must be accepted")
	}
	if !p.authorized(httptest.NewRequest(http.MethodGet, "http://example.com/?access_token=secret", nil)) {
		t.Fatal("correct query token must be accepted")
	}
}

func TestIngressProxyEndToEnd(t *testing.T) {
	var gotHost string
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		fmt.Fprint(w, "ok")
	}))
	defer guest.Close()

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(guest.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var guestPort int
	if _, err := fmt.Sscanf(portStr, "%d", &guestPort); err != nil {
		t.Fatal(err)
	}

	m := PortMapping{
		TaskID:          "web",
		HostPort:        0, // ephemeral; the test reads the bound address
		GuestPort:       guestPort,
		GuestIP:         "127.0.0.1",
		AccessToken:     "tok",
		MaskRequestHost: "masked.internal",
	}
	if err := startIngressProxy(m); err != nil {
		t.Fatal(err)
	}
	defer stopIngressProxy("web", 0)

	ingressMu.Lock()
	p := ingressProxies[ingressKey("web", 0)]
	ingressMu.Unlock()
	if p == nil {
		t.Fatal("proxy not registered")
	}
	addr := p.ln.Addr().String()
	base := "http://" + addr

	client := &http.Client{Timeout: 5 * time.Second}

	// No token -> 401.
	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong token -> 401.
	req, _ := http.NewRequest(http.MethodGet, base+"/", nil)
	req.Header.Set(ingressHeaderToken, "wrong")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Correct token -> 200, and the guest sees the masked Host.
	req, _ = http.NewRequest(http.MethodGet, base+"/", nil)
	req.Header.Set(ingressHeaderToken, "tok")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("correct token: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	if gotHost != "masked.internal" {
		t.Fatalf("guest saw Host %q, want masked.internal", gotHost)
	}
}
