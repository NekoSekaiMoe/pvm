package network

import (
	"fmt"
	"strings"
	"testing"
)

func TestIPAM_AllocateStartsAtDot100(t *testing.T) {
	a, err := NewIPAM("10.0.0.1/24")
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	ip, err := a.Allocate("task-1")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if got := ip.String(); got != "10.0.0.100" {
		t.Errorf("first allocation = %s, want 10.0.0.100", got)
	}
	ip2, err := a.Allocate("task-2")
	if err != nil {
		t.Fatalf("Allocate task-2: %v", err)
	}
	if got := ip2.String(); got != "10.0.0.101" {
		t.Errorf("second allocation = %s, want 10.0.0.101", got)
	}
}

func TestIPAM_DefaultCIDRAndGatewaySkip(t *testing.T) {
	a, err := NewIPAM("")
	if err != nil {
		t.Fatalf("NewIPAM default: %v", err)
	}
	if got := a.GatewayIP().String(); got != "10.0.0.1" {
		t.Errorf("default gateway = %s, want 10.0.0.1", got)
	}
	// A gateway sitting at .100 must be skipped by the allocator.
	b, err := NewIPAM("192.168.55.100/24")
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	ip, err := b.Allocate("t")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if got := ip.String(); got != "192.168.55.101" {
		t.Errorf("allocation with gateway at .100 = %s, want 192.168.55.101", got)
	}
}

func TestIPAM_IdempotentSameTask(t *testing.T) {
	a, _ := NewIPAM("10.0.0.1/24")
	first, err := a.Allocate("task-x")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	again, err := a.Allocate("task-x")
	if err != nil {
		t.Fatalf("re-Allocate: %v", err)
	}
	if !first.Equal(again) {
		t.Errorf("re-allocation for same task = %s, want stable %s", again, first)
	}
}

func TestIPAM_ReleaseReuse(t *testing.T) {
	a, _ := NewIPAM("10.0.0.1/24")
	ip, err := a.Allocate("task-a")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	a.Release("task-a")
	a.Release("task-a") // double release is a no-op
	reused, err := a.Allocate("task-b")
	if err != nil {
		t.Fatalf("Allocate after release: %v", err)
	}
	if !reused.Equal(ip) {
		t.Errorf("released address %s not reused, got %s", ip, reused)
	}
}

func TestIPAM_Exhaustion(t *testing.T) {
	// /30 has exactly two usable host addresses: .1 (gateway) and .2.
	// Starting offset .100 lies outside, so allocation must exhaust
	// immediately rather than hand out the broadcast/network address.
	a, err := NewIPAM("10.9.0.1/30")
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	if _, err := a.Allocate("task-1"); err == nil {
		t.Fatal("expected exhaustion error on /30 with start offset .100")
	} else if !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIPAM_SmallSubnetExhaustion(t *testing.T) {
	// Shift the start offset out of the equation by using a /24 and filling
	// it: allocate until the error, then prove the count is bounded.
	a, _ := NewIPAM("10.5.0.1/24")
	n := 0
	for i := 0; ; i++ {
		if _, err := a.Allocate(fmt.Sprintf("task-%d", i)); err != nil {
			break
		}
		n++
	}
	// Usable from .100..254 = 155 addresses.
	if n != 155 {
		t.Errorf("allocated %d addresses before exhaustion, want 155", n)
	}
}

func TestIPAM_AllocateGuestOverride(t *testing.T) {
	a, _ := NewIPAM("10.0.0.1/24")
	ip, err := a.AllocateGuest("task-g", "10.0.0.77")
	if err != nil {
		t.Fatalf("AllocateGuest: %v", err)
	}
	if got := ip.String(); got != "10.0.0.77" {
		t.Errorf("override allocation = %s, want 10.0.0.77", got)
	}
	// The pinned address is taken: auto-allocation must skip it, and a
	// second task pinning the same address must fail.
	if _, err := a.AllocateGuest("task-h", "10.0.0.77"); err == nil {
		t.Error("expected collision error for a second task on the same guest_ip")
	}
	for i := 0; i < 200; i++ {
		auto, err := a.Allocate(fmt.Sprintf("auto-%d", i))
		if err != nil {
			break
		}
		if auto.String() == "10.0.0.77" {
			t.Fatal("auto allocator handed out the pinned address")
		}
	}
	// Release makes the pinned address available again.
	a.Release("task-g")
	if _, err := a.AllocateGuest("task-h", "10.0.0.77"); err != nil {
		t.Errorf("AllocateGuest after release: %v", err)
	}
}

func TestIPAM_AllocateGuestValidation(t *testing.T) {
	a, _ := NewIPAM("10.0.0.1/24")
	cases := map[string]string{
		"not-an-ip":   "valid IPv4",
		"10.0.1.5":    "outside the bridge subnet",
		"10.0.0.1":    "collides with the gateway",
		"10.0.0.0":    "network/broadcast",
		"10.0.0.255":  "network/broadcast",
		"2001:db8::1": "valid IPv4",
	}
	for ip, want := range cases {
		if _, err := a.AllocateGuest("t", ip); err == nil {
			t.Errorf("AllocateGuest(%q): expected error containing %q", ip, want)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("AllocateGuest(%q) error = %v, want substring %q", ip, err, want)
		}
	}
}

func TestIPAM_InvalidCIDR(t *testing.T) {
	for _, cidr := range []string{"junk", "10.0.0.1", "10.0.0.1/33", "fd00::1/64", "10.0.0.1/31"} {
		if _, err := NewIPAM(cidr); err == nil {
			t.Errorf("NewIPAM(%q): expected error", cidr)
		}
	}
}

func TestSharedIPAM_SharesBySubnet(t *testing.T) {
	a, err := SharedIPAM("10.77.0.1/24")
	if err != nil {
		t.Fatalf("SharedIPAM: %v", err)
	}
	b, err := SharedIPAM("") // default differs; separate allocator
	if err != nil {
		t.Fatalf("SharedIPAM default: %v", err)
	}
	a2, err := SharedIPAM("10.77.0.1/24")
	if err != nil {
		t.Fatalf("SharedIPAM again: %v", err)
	}
	if a != a2 {
		t.Error("SharedIPAM did not return the same instance for the same subnet")
	}
	if a == b {
		t.Error("SharedIPAM conflated distinct subnets")
	}
	// Cross-instance visibility: an address taken via the shared instance is
	// invisible to a fresh NewIPAM — which is exactly why callers must go
	// through SharedIPAM.
	ip, err := a.Allocate("p1a-shared-check")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer a.Release("p1a-shared-check")
	if _, err := a2.AllocateGuest("p1a-shared-check-2", ip.String()); err == nil {
		t.Error("shared instance allowed a duplicate of an in-use address")
	}
}
