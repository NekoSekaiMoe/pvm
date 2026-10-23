package network

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngressProxyTokenAndHostMask(t *testing.T) {
	var forwarded atomic.Int32
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "path": r.URL.Path})
	}))
	t.Cleanup(guest.Close)
	guestAddr := guest.Listener.Addr().(*net.TCPAddr)
	mapping := PortMapping{
		TaskID: "ingress-test", GuestIP: "127.0.0.1", GuestPort: guestAddr.Port,
		AccessToken: "test-access-token", MaskRequestHost: "private.example",
	}
	// Port zero lets the OS allocate a free listener without a probe/bind race.
	if err := startIngressProxy(mapping); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopIngressProxy(mapping.TaskID, mapping.HostPort) })
	ingressMu.Lock()
	proxy := ingressProxies[ingressKey(mapping.TaskID, mapping.HostPort)]
	ingressMu.Unlock()
	addr := "http://127.0.0.1:" + strconv.Itoa(proxy.ln.Addr().(*net.TCPAddr).Port)
	client := &http.Client{Timeout: 3 * time.Second}
	for _, tc := range []struct {
		name, header, query string
		want                int
	}{
		{"missing token", "", "", http.StatusUnauthorized},
		{"wrong token", "wrong", "", http.StatusUnauthorized},
		{"header token", mapping.AccessToken, "", http.StatusOK},
		{"query token", "", "?access_token=" + mapping.AccessToken, http.StatusOK},
		{"wrong header overrides query", "wrong", "?access_token=" + mapping.AccessToken, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := forwarded.Load()
			req, err := http.NewRequest(http.MethodGet, addr+"/workspace"+tc.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "public.example"
			req.Header.Set(ingressHeaderToken, tc.header)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			if tc.want == http.StatusUnauthorized {
				if forwarded.Load() != before {
					t.Fatal("unauthorized request reached the guest")
				}
				return
			}
			var got map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got["host"] != mapping.MaskRequestHost || got["path"] != "/workspace" {
				t.Fatalf("guest request = %v", got)
			}
		})
	}
	stopIngressProxy(mapping.TaskID, mapping.HostPort)
	if resp, err := client.Get(addr); err == nil {
		resp.Body.Close()
		t.Fatal("stopped ingress proxy still accepts requests")
	}
}

func TestIngressMappingValidation(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, token, host string
		valid                       bool
	}{
		{"token over TCP", "tcp", "token", "", true},
		{"host mask over default TCP", "", "", "private.example:8080", true},
		{"plain UDP", "udp", "", "", true},
		{"token over UDP", "udp", "token", "", false},
		{"host mask over UDP", "udp", "", "private.example", false},
		{"oversized token", "tcp", strings.Repeat("x", maxIngressTokenBytes+1), "", false},
		{"oversized host", "tcp", "", strings.Repeat("x", maxIngressHostBytes+1), false},
		{"host header injection", "tcp", "", "private.example\r\nX-Injected: true", false},
		{"host contains path", "tcp", "", "private.example/path", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePortMapping(PortMapping{
				TaskID: "ingress-test", HostPort: 8080, GuestPort: 80, GuestIP: "10.0.0.2",
				Protocol: tc.protocol, AccessToken: tc.token, MaskRequestHost: tc.host,
			})
			if (err == nil) != tc.valid {
				t.Fatalf("validatePortMapping = %v, valid = %v", err, tc.valid)
			}
		})
	}
}
