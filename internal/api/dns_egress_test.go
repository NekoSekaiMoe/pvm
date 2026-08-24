package api

import (
	"net/http"
	"strings"
	"testing"

	"uml-container/internal/network/dnslearn"
)

// cleanupLearner removes a learner registered through the API so the
// process-local registry does not leak across tests.
func cleanupLearner(t *testing.T, task string) {
	t.Helper()
	t.Cleanup(func() {
		if l := dnslearn.For(task); l != nil {
			dnslearn.Unregister(task, l)
			l.Close()
		}
	})
}

// TestAPI_DNSEgress covers the P1-B REST surface: 404s before a learner
// exists, on-demand enable via PUT policy, promote + immediate-learn (with
// an unreachable upstream reporting learn_error, not a failed promote),
// drop, and per-task isolation. The fake-upstream happy path is exercised
// end-to-end by tests/34_test_dns_egress_policy.sh.
func TestAPI_DNSEgress(t *testing.T) {
	resetPlanes(t)
	base := bootServer(t)

	// Unknown task: 404 on both read endpoints.
	resp, _ := doJSON(t, "GET", base, "/api/egress/tkdns/learned", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET learned unknown task: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "GET", base, "/api/egress/tkdns/policy", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET policy unknown task: %d", resp.StatusCode)
	}
	// Disabling a task that never learned must not silently create one.
	resp, _ = doJSON(t, "PUT", base, "/api/egress/tkdns/policy",
		map[string]interface{}{"dns_learn_enabled": false})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("PUT disable without learner: %d, want 404", resp.StatusCode)
	}

	// Enable on demand; upstream points at a closed port so LearnNow fails
	// fast (the promote must still succeed).
	resp, out := doJSON(t, "PUT", base, "/api/egress/tkdns/policy", map[string]interface{}{
		"dns_learn_enabled": true,
		"learn_ttl":         "30s",
		"dns_upstream":      "127.0.0.1:1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT enable: %d %v", resp.StatusCode, out)
	}
	if out["dns_learn_enabled"] != true || out["learn_ttl"] != "30s" {
		t.Fatalf("policy view wrong: %v", out)
	}
	addr, _ := out["dns_addr"].(string)
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("control-plane learner must bind loopback, got %q", addr)
	}
	cleanupLearner(t, "tkdns")

	// Malformed domains are rejected before touching the allowlist.
	resp, _ = doJSON(t, "POST", base, "/api/egress/tkdns/allow",
		map[string]interface{}{"domain": "evil.com:80/x"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST allow bad domain: %d, want 400", resp.StatusCode)
	}

	// Promote: allowlist grows even though immediate learning fails (no
	// resolver behind 127.0.0.1:1).
	resp, out = doJSON(t, "POST", base, "/api/egress/tkdns/allow",
		map[string]interface{}{"domain": "example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST allow: %d %v", resp.StatusCode, out)
	}
	if out["added_to_allowlist"] != true {
		t.Fatalf("promote not recorded: %v", out)
	}
	if out["learn_error"] == nil {
		t.Fatalf("unreachable upstream must surface learn_error: %v", out)
	}

	// The live policy view shows the promoted domain.
	resp, out = doJSON(t, "GET", base, "/api/egress/tkdns/policy", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET policy: %d", resp.StatusCode)
	}
	doms, _ := out["allow_domains"].([]interface{})
	found := false
	for _, d := range doms {
		if d == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("promoted domain missing from policy view: %v", out)
	}

	// Toggle off/on.
	resp, out = doJSON(t, "PUT", base, "/api/egress/tkdns/policy",
		map[string]interface{}{"dns_learn_enabled": false})
	if resp.StatusCode != http.StatusOK || out["dns_learn_enabled"] != false {
		t.Fatalf("PUT disable: %d %v", resp.StatusCode, out)
	}
	// Changing creation-time parameters on a live learner is a 400, not a
	// silent no-op.
	resp, _ = doJSON(t, "PUT", base, "/api/egress/tkdns/policy",
		map[string]interface{}{"dns_upstream": "1.1.1.1:53"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT upstream change: %d, want 400", resp.StatusCode)
	}
	resp, _ = doJSON(t, "PUT", base, "/api/egress/tkdns/policy",
		map[string]interface{}{"learn_ttl": "bogus"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT bad ttl: %d, want 400", resp.StatusCode)
	}

	// Drop on an empty set is a clean 0.
	resp, out = doJSON(t, "DELETE", base, "/api/egress/tkdns/learned/example.com", nil)
	if resp.StatusCode != http.StatusOK || out["dropped"] != float64(0) {
		t.Fatalf("DELETE learned: %d %v", resp.StatusCode, out)
	}

	// Isolation: a second task's learner does not see tkdns' allowlist.
	resp, _ = doJSON(t, "PUT", base, "/api/egress/tkdns2/policy",
		map[string]interface{}{"dns_learn_enabled": true, "dns_upstream": "127.0.0.1:1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT enable tkdns2: %d", resp.StatusCode)
	}
	cleanupLearner(t, "tkdns2")
	resp, out = doJSON(t, "GET", base, "/api/egress/tkdns2/policy", nil)
	doms, _ = out["allow_domains"].([]interface{})
	for _, d := range doms {
		if d == "example.com" {
			t.Fatalf("task isolation broken: tkdns2 sees tkdns' domain: %v", out)
		}
	}
}
