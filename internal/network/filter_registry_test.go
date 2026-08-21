package network

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// newTestMap creates a tiny real eBPF map (array of one u32) so the registry
// tests exercise genuine Map semantics (Close, identity) without root.
func newTestMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}, ebpf.MapOptions{})
	// Map creation needs privilege (or unprivileged BPF + MEMLOCK headroom);
	// on hosts without it we skip, matching the ip/tc skips in
	// network_test.go — the registry bookkeeping under test is pure Go state.
	if err != nil {
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("eBPF map creation not permitted on this host (root/MEMLOCK required): %v", err)
		}
		t.Fatalf("NewMapWithOptions: %v", err)
	}
	return m
}

// TestWhitelistRegistry_PerTapIsolation pins that maps are registered per
// tap and that looking up an unknown tap yields nil — replacing the former
// package-global WhitelistMap that let containers see (and mutate) each
// other's policy.
func TestWhitelistRegistry_PerTapIsolation(t *testing.T) {
	if WhitelistMapFor("no-such-tap") != nil {
		t.Fatal("unknown tap returned non-nil map")
	}
	m1 := newTestMap(t)
	defer m1.Close()
	m2 := newTestMap(t)
	defer m2.Close()

	registerWhitelistMap("tapA", m1)
	registerWhitelistMap("tapB", m2)
	defer unregisterWhitelistMap("tapA", m1)
	defer unregisterWhitelistMap("tapB", m2)

	if got := WhitelistMapFor("tapA"); got != m1 {
		t.Fatalf("tapA map = %v, want the registered map", got)
	}
	if got := WhitelistMapFor("tapB"); got != m2 {
		t.Fatalf("tapB map = %v, want the registered map", got)
	}
}

// TestWhitelistRegistry_ReattachClosesOldMap pins the fd-leak fix: attaching
// again for the same tap closes the previously registered map instead of
// leaving it open forever.
func TestWhitelistRegistry_ReattachClosesOldMap(t *testing.T) {
	m1 := newTestMap(t)
	m2 := newTestMap(t)
	defer m2.Close()

	registerWhitelistMap("tapC", m1)
	registerWhitelistMap("tapC", m2) // re-attach: m1 must be closed

	// A closed cilium/ebpf map reports FD() == -1.
	if fd := m1.FD(); fd != -1 {
		t.Fatalf("old map still open after re-attach (fd %d), want closed", fd)
	}
	if got := WhitelistMapFor("tapC"); got != m2 {
		t.Fatalf("tapC map = %v, want the replacement map", got)
	}
	unregisterWhitelistMap("tapC", m2)
}

// TestWhitelistRegistry_UnregisterOnlyOwnMap pins that unregistering with a
// stale map pointer leaves the current registration intact.
func TestWhitelistRegistry_UnregisterOnlyOwnMap(t *testing.T) {
	m1 := newTestMap(t)
	defer m1.Close()
	m2 := newTestMap(t)
	defer m2.Close()

	registerWhitelistMap("tapD", m1)
	unregisterWhitelistMap("tapD", m2) // wrong map: must be ignored
	if got := WhitelistMapFor("tapD"); got != m1 {
		t.Fatalf("tapD map = %v, want original registration kept", got)
	}
	unregisterWhitelistMap("tapD", m1)
	if got := WhitelistMapFor("tapD"); got != nil {
		t.Fatalf("tapD map = %v after unregister, want nil", got)
	}
}
