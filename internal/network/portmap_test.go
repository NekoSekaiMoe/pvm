package network

// portmap_test.go — pure pieces of the inbound DNAT mapping layer: rule
// argv construction (apply/remove symmetry), validation, and the durable
// registry round-trip. Rule EXECUTION needs root+iptables and is covered
// by the integration suites instead.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortMapRulesApplyRemoveSymmetry(t *testing.T) {
	m := PortMapping{TaskID: "web", HostPort: 8080, GuestPort: 80, GuestIP: "10.0.0.100", Protocol: "tcp"}
	on := portMapRules(m, true)
	off := portMapRules(m, false)
	if len(on) != 3 || len(off) != 3 {
		t.Fatalf("expected 3 rule sets each, got %d/%d", len(on), len(off))
	}
	for i := range on {
		// Exactly one action token per rule; identical match spec otherwise.
		norm := func(argv []string, want string) (string, bool) {
			var rest []string
			found := false
			for _, tok := range argv {
				if tok == want && !found {
					found = true
					continue
				}
				rest = append(rest, tok)
			}
			return strings.Join(rest, " "), found
		}
		onRest, onOk := norm(on[i], "-A")
		offRest, offOk := norm(off[i], "-D")
		if !onOk || !offOk || onRest != offRest {
			t.Fatalf("rule %d: apply/remove specs drifted:\n%v\n%v", i, on[i], off[i])
		}
	}
	// The three chains: PREROUTING DNAT, OUTPUT DNAT, FORWARD accept.
	if !strings.Contains(strings.Join(on[0], " "), "PREROUTING") ||
		!strings.Contains(strings.Join(on[1], " "), "OUTPUT") ||
		!strings.Contains(strings.Join(on[2], " "), "FORWARD") {
		t.Fatalf("missing chains: %v", on)
	}
	if !strings.Contains(strings.Join(on[0], " "), "--to-destination 10.0.0.100:80") {
		t.Fatalf("PREROUTING must DNAT to guest: %v", on[0])
	}
}

func TestPortMapRulesDefaultProtocol(t *testing.T) {
	m := PortMapping{TaskID: "u", HostPort: 53, GuestPort: 5353, GuestIP: "10.0.0.5"}
	for _, argv := range portMapRules(m, true) {
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, "-p tcp") {
			t.Fatalf("empty protocol must default to tcp: %v", argv)
		}
	}
}

func TestValidatePortMapping(t *testing.T) {
	ok := PortMapping{TaskID: "t", HostPort: 1, GuestPort: 65535, GuestIP: "10.0.0.1", Protocol: "udp"}
	if err := validatePortMapping(ok); err != nil {
		t.Fatalf("valid mapping rejected: %v", err)
	}
	bad := []struct {
		name string
		m    PortMapping
	}{
		{"host port zero", PortMapping{TaskID: "t", HostPort: 0, GuestPort: 80, GuestIP: "10.0.0.1"}},
		{"host port too high", PortMapping{TaskID: "t", HostPort: 70000, GuestPort: 80, GuestIP: "10.0.0.1"}},
		{"guest port zero", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 0, GuestIP: "10.0.0.1"}},
		{"guest ip garbage", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "not-an-ip"}},
		{"guest ip ipv6", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "::1"}},
		{"protocol not tcp/udp", PortMapping{TaskID: "t", HostPort: 80, GuestPort: 80, GuestIP: "10.0.0.1", Protocol: "sctp"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePortMapping(tc.m); err == nil {
				t.Fatalf("must be rejected: %+v", tc.m)
			}
		})
	}
}

// TestPortMapRegistryHonorsStateRootEnv pins the 404-vs-500 contract:
// the lazy callers pass no explicit root, so the registry MUST follow
// $PVM_STATE_ROOT (mirroring state.RootDir). With the historical
// hardcoded /var/lib/uml-container default, an unprivileged runner
// (e.g. a Bazel sh_test) could not create the directory and every portmap
// request surfaced the mkdir error instead — DELETE of a nonexistent
// mapping answered 500, not 404.
func TestPortMapRegistryHonorsStateRootEnv(t *testing.T) {
	portMapRegistry_ = nil // reset the singleton
	defer func() { portMapRegistry_ = nil }()
	root := t.TempDir()
	t.Setenv("PVM_STATE_ROOT", root)
	// Seed a persisted mapping; a registry honoring the env root must
	// surface it (the historical hardcoded /var/lib default would load a
	// different, empty registry).
	seed := `{"mappings":[{"task":"web","host_port":8080,"guest_port":80,"guest_ip":"10.0.0.100","protocol":"tcp","created_at":"2025-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(root, "portmappings.json"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := PortMappingsFor("web"); len(got) != 1 || got[0].HostPort != 8080 {
		t.Fatalf("registry did not load from $PVM_STATE_ROOT: %+v", got)
	}
	if err := DeletePortMapping("no-such-task", 9999, "tcp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delete of a nonexistent mapping must surface os.ErrNotExist (the API maps it to 404), got %v", err)
	}
}

func TestPortMapRegistryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	portMapRegistry_ = nil // reset the singleton
	r, err := LoadPortMapRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.mappings["web"] = []PortMapping{
		{TaskID: "web", HostPort: 8080, GuestPort: 80, GuestIP: "10.0.0.100", Protocol: "tcp"},
		{TaskID: "web", HostPort: 5353, GuestPort: 53, GuestIP: "10.0.0.100", Protocol: "udp"},
	}
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	// A fresh load (simulating restart) must see the same mappings.
	portMapRegistry_ = nil
	r2, err := LoadPortMapRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r2.mappings["web"]); got != 2 {
		t.Fatalf("reloaded %d mappings, want 2", got)
	}
	if got := PortMappingsFor("web"); len(got) != 2 {
		t.Fatalf("PortMappingsFor = %d, want 2", len(got))
	}
	// Registry file lives where the network registry does.
	if !strings.HasPrefix(r.path, filepath.Join(dir, "portmappings.json")) && r.path != filepath.Join(dir, "portmappings.json") {
		t.Fatalf("unexpected registry path %s", r.path)
	}
}
