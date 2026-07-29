package ebpf

import (
	"net"
	"strings"
	"testing"
)

// TestUpdateWhitelist_RequiresPinnedMap verifies that without a pinned BPF
// map (the normal case in CI / non-root), UpdateWhitelist fails fast at the
// LoadPinnedMap step before touching any syscalls. This guards the early-out.
func TestUpdateWhitelist_RequiresPinnedMap(t *testing.T) {
	err := UpdateWhitelist("example.com", "203.0.113.5")
	if err == nil {
		t.Skip("a pinned whitelist_map exists on this host; cannot assert absence path")
	}
	if !strings.Contains(err.Error(), "pinned map") {
		t.Errorf("expected error about pinned map, got: %v", err)
	}
}

func TestIPValidationPure(t *testing.T) {
	// Independent sanity check of the parsing rules UpdateWhitelist relies on,
	// so the test still documents intent even if the function body changes.
	valid := net.ParseIP("203.0.113.5")
	if valid == nil || valid.To4() == nil {
		t.Errorf("203.0.113.5 should be a valid IPv4")
	}
	if net.ParseIP("not-an-ip") != nil {
		t.Errorf("'not-an-ip' should not parse")
	}
	v6 := net.ParseIP("2001:db8::1")
	if v6 == nil || v6.To4() != nil {
		t.Errorf("2001:db8::1 handling wrong")
	}
}
