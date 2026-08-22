package network

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
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
	// ENOMEM is an environment-level allocation failure (kernel refuses to
	// allocate map memory under pressure), not a defect under test.
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) ||
			errors.Is(err, syscall.ENOMEM) ||
			strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("eBPF map creation unavailable on this host (root/MEMLOCK/memory required): %v", err)
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

// TestWhitelistRegistry_ReattachKeepsReferencedMapAlive pins the
// refcounting contract: a map obtained via WhitelistMapFor stays open
// across a re-attach that replaces it, and is closed only once the caller
// releases its (last) reference — never immediately under its feet.
func TestWhitelistRegistry_ReattachKeepsReferencedMapAlive(t *testing.T) {
	m1 := newTestMap(t)
	m2 := newTestMap(t)
	defer m2.Close()

	registerWhitelistMap("tapE", m1)
	held := WhitelistMapFor("tapE") // take a reference on m1
	if held != m1 {
		t.Fatalf("tapE map = %v, want the registered m1", held)
	}

	registerWhitelistMap("tapE", m2) // re-attach while m1 is referenced
	if fd := m1.FD(); fd == -1 {
		t.Fatal("referenced map closed by re-attach; must stay alive until released")
	}
	if got := WhitelistMapFor("tapE"); got != m2 {
		t.Fatalf("tapE map = %v, want the replacement m2", got)
	}
	ReleaseWhitelistMap("tapE", m2) // drop the lookup reference we just took

	ReleaseWhitelistMap("tapE", m1) // last reference on the retired map
	if fd := m1.FD(); fd != -1 {
		t.Fatalf("retired map still open after last release (fd %d), want closed", fd)
	}

	// The replacement itself still closes on unregister (no references).
	unregisterWhitelistMap("tapE", m2)
	if fd := m2.FD(); fd != -1 {
		t.Fatalf("replacement map still open after unregister (fd %d), want closed", fd)
	}
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
