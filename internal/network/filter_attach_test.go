package network

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// TestLoadBpfSpec_ExemptConstants proves the embedded (regenerated) BPF
// object actually carries the load-time constants AttachEgressFilter
// rewrites. LoadCollectionSpec parsing and RewriteConstants are pure
// userspace operations — no root, no bpffs needed. If bpf/egress.c loses
// the const volatile declarations without a regen, this fails.
func TestLoadBpfSpec_ExemptConstants(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		if errors.Is(err, ErrBpfNotGenerated) {
			t.Skip("compiled BPF objects not generated in this checkout")
		}
		t.Fatalf("loadBpf: %v", err)
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"exempt_ip_a": uint32(0x0A000001),
		"exempt_ip_b": uint32(0x0A000064),
	})
	if err != nil {
		t.Fatalf("RewriteConstants: %v (regenerate bpf_bpf*.go after C edits)", err)
	}
}

// TestBpfIPv4 checks the host-order rendering the loader rewrites into
// exempt_ip_a/b: on any architecture the rendered value must round-trip the
// four network-order bytes through native byte order (matching how the BPF
// program loads ip->daddr).
func TestBpfIPv4(t *testing.T) {
	if got := bpfIPv4(net.ParseIP("10.0.0.1")); got == 0 {
		t.Error("bpfIPv4(10.0.0.1) = 0, want non-zero")
	}
	if got := bpfIPv4(net.ParseIP("2001:db8::1")); got != 0 {
		t.Errorf("bpfIPv4(IPv6) = %#x, want 0 (unset)", got)
	}
	if got := bpfIPv4(nil); got != 0 {
		t.Errorf("bpfIPv4(nil) = %#x, want 0 (unset)", got)
	}
	// Distinct addresses must render distinctly (endianness-independent).
	if bpfIPv4(net.ParseIP("10.0.0.1")) == bpfIPv4(net.ParseIP("10.0.0.2")) {
		t.Error("bpfIPv4 conflated .1 and .2")
	}
}

func TestWhitelistPinPath_Validation(t *testing.T) {
	p, err := WhitelistPinPath("task-1_A")
	if err != nil {
		t.Fatalf("WhitelistPinPath: %v", err)
	}
	if p != bpfPinRoot+"/task-1_A/whitelist_map" {
		t.Errorf("pin path = %s", p)
	}
	for _, bad := range []string{"", "../escape", "a/b", "a.b", "a b"} {
		if _, err := WhitelistPinPath(bad); err == nil {
			t.Errorf("WhitelistPinPath(%q): expected rejection", bad)
		}
	}
}

// TestAttachEgressFilter_TypedError: every failure of the attach path must
// come back as *EgressFilterError so the manager can classify the degraded
// mode. A bogus tap name guarantees failure at the latest at the link
// lookup — usually much earlier (LoadAndAssign needs CAP_BPF). Either way
// the error must be typed, never bare.
func TestAttachEgressFilter_TypedError(t *testing.T) {
	_, err := AttachEgressFilter("definitely-not-a-real-device-!@#", "p1a-test",
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.100"))
	if err == nil {
		t.Fatal("attach on a bogus tap succeeded; environment is unexpectedly capable")
	}
	var efErr *EgressFilterError
	if !errors.As(err, &efErr) {
		t.Fatalf("error is %T, want *EgressFilterError: %v", err, err)
	}
	if efErr.Op == "" || efErr.Tap == "" {
		t.Errorf("typed error lacks Op/Tap: %+v", efErr)
	}
}

// TestAttachEgressFilter_InvalidTaskID: path-safety validation fires before
// any privileged operation, so this passes with or without root.
func TestAttachEgressFilter_InvalidTaskID(t *testing.T) {
	_, err := AttachEgressFilter("tap0", "../etc",
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.100"))
	var efErr *EgressFilterError
	if !errors.As(err, &efErr) || efErr.Op != "validate" {
		t.Fatalf("expected validate-stage typed error, got: %v", err)
	}
}

// TestAddWhitelistEntry_NoMap: with no in-process registry entry and no
// pinned map (the normal CI situation), the update must fail with a clear
// pinned-map error rather than panicking or silently succeeding.
func TestAddWhitelistEntry_NoMap(t *testing.T) {
	err := AddWhitelistEntry("p1a-no-such-task", "", "203.0.113.5")
	if err == nil {
		t.Skip("a pinned map for p1a-no-such-task exists on this host")
	}
	if !strings.Contains(err.Error(), "pinned map") {
		t.Errorf("expected pinned-map error, got: %v", err)
	}
	if err := AddWhitelistEntry("t", "", "not-an-ip"); err == nil ||
		!strings.Contains(err.Error(), "invalid whitelist IP") {
		t.Errorf("bad IP must be rejected before touching any map, got: %v", err)
	}
	if err := AddWhitelistEntry("t", "", "2001:db8::1"); err == nil ||
		!strings.Contains(err.Error(), "only IPv4") {
		t.Errorf("IPv6 must be rejected, got: %v", err)
	}
}

// TestDetachTaskFilter_Idempotent: teardown of a task that never attached
// must be a silent no-op (StartTask defers it unconditionally).
func TestDetachTaskFilter_Idempotent(t *testing.T) {
	if err := DetachTaskFilter("p1a-never-attached", "p1a-no-such-tap"); err != nil {
		t.Errorf("DetachTaskFilter on unattached task: %v", err)
	}
}
