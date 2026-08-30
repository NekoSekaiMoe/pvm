package network

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
)

// TestIsDeviceNotExist pins down which `ip link delete` failures DeleteBridge
// is allowed to swallow: only "the device is gone" may be treated as success.
// Permission errors, busy devices and malformed names must propagate so the
// caller's refcount/ip_forward bookkeeping stays honest.
func TestIsDeviceNotExist(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"cannot find device", errors.New(`Cannot find device "pvm0"`), true},
		{"cannot find device uppercase", errors.New(`CANNOT FIND DEVICE "pvm0"`), true},
		{"device not found", errors.New("Device not found"), true},
		{"no such device", errors.New("RTNETLINK answers: no such device"), true},
		{"permission denied", errors.New("RTNETLINK answers: Operation not permitted"), false},
		{"device busy", errors.New("RTNETLINK answers: Device or resource busy"), false},
		{"invalid name", errors.New(`Error: argument "!!!" is wrong: "name" not a valid ifname`), false},
		{"empty message", errors.New(""), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isDeviceNotExist(c.err); got != c.want {
				t.Errorf("isDeviceNotExist(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// stubExecRun replaces execRun with a recorder that succeeds every command
// and returns the recorded "name arg..." invocations. Restored on cleanup.
func stubExecRun(t *testing.T) *[]string {
	t.Helper()
	orig := execRun
	var calls []string
	execRun = func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { execRun = orig })
	return &calls
}

// TestDeleteBridge_InvalidCIDRSkipped pins down the contract that an
// unparseable gatewayIP is skipped for the iptables cleanup but does not
// abort the bridge teardown itself: no iptables invocation may happen, while
// the `ip link` teardown must still run with the exact expected arguments.
func TestDeleteBridge_InvalidCIDRSkipped(t *testing.T) {
	calls := stubExecRun(t)
	// The interface name is syntactically valid so that an `ip` argument
	// validation error cannot masquerade as the behavior under test.
	if err := DeleteBridge("pvmtest-nonexistent0", "not-a-cidr"); err != nil {
		t.Fatalf("DeleteBridge with invalid CIDR returned error, want it skipped: %v", err)
	}
	for _, c := range *calls {
		if strings.HasPrefix(c, "iptables") {
			t.Errorf("iptables cleanup ran despite unparseable CIDR: %q", c)
		}
	}
	wantDown := "ip link set pvmtest-nonexistent0 down"
	wantDel := "ip link delete pvmtest-nonexistent0 type bridge"
	got := strings.Join(*calls, "\n")
	if !strings.Contains(got, wantDown) {
		t.Errorf("missing %q in teardown commands:\n%s", wantDown, got)
	}
	if !strings.Contains(got, wantDel) {
		t.Errorf("missing %q in teardown commands:\n%s", wantDel, got)
	}
}

// TestDeleteBridge_ValidCIDRTeardown asserts that a parseable gatewayIP
// produces the symmetric iptables -D cleanup (against the masked subnet, not
// the raw gateway) followed by the `ip link` teardown.
func TestDeleteBridge_ValidCIDRTeardown(t *testing.T) {
	calls := stubExecRun(t)
	if err := DeleteBridge("pvmtest0", "10.200.1.1/24"); err != nil {
		t.Fatalf("DeleteBridge returned error: %v", err)
	}
	want := []string{
		"iptables -t nat -D POSTROUTING -s 10.200.1.0/24 ! -o pvmtest0 -j MASQUERADE",
		"iptables -D FORWARD -s 10.200.1.0/24 -j ACCEPT",
		"iptables -D FORWARD -d 10.200.1.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"ip link set pvmtest0 down",
		"ip link delete pvmtest0 type bridge",
	}
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("teardown commands mismatch:\n got: %q\nwant: %q", *calls, want)
	}
}

// resetForwardState normalizes the package-level ip_forward bookkeeping so
// refcount assertions are deterministic regardless of test order.
func resetForwardState(t *testing.T) {
	t.Helper()
	ipForwardMu.Lock()
	ipForwardRefCount = 0
	ipForwardOriginal = ""
	ipForwardMu.Unlock()
	t.Cleanup(func() {
		ipForwardMu.Lock()
		ipForwardRefCount = 0
		ipForwardOriginal = ""
		ipForwardMu.Unlock()
	})
}

// stubReadIPForward pins the sysctl read to "0" (SetupBridge then records it
// as the original value to restore).
func stubReadIPForward(t *testing.T) {
	t.Helper()
	orig := readIPForward
	readIPForward = func() (string, error) { return "0", nil }
	t.Cleanup(func() { readIPForward = orig })
}

// failOn returns an execRun stub that succeeds for every command except
// those whose joined invocation contains substr.
func failOn(t *testing.T, substr string, calls *[]string) {
	t.Helper()
	orig := execRun
	execRun = func(name string, args ...string) error {
		inv := name + " " + strings.Join(args, " ")
		*calls = append(*calls, inv)
		if strings.Contains(inv, substr) {
			return errors.New("injected failure: " + inv)
		}
		return nil
	}
	t.Cleanup(func() { execRun = orig })
}

// TestSetupBridge_RollbackBeforeRefcount asserts that a failure BEFORE the
// ip_forward refcount is incremented rolls back the bridge (and nothing
// else): the refcount must stay at 0 — the old code's rollback path called
// DeleteBridge, which decremented a count it did not own.
func TestSetupBridge_RollbackBeforeRefcount(t *testing.T) {
	resetForwardState(t)
	stubReadIPForward(t)
	calls := stubExecRun(t)
	failOn(t, "ip addr add", calls) // fail before NAT setup and refcount++

	err := SetupBridge("pvmbr0", "", "10.0.0.1/24")
	if err == nil {
		t.Fatal("SetupBridge expected to fail on injected ip addr add error")
	}
	ipForwardMu.Lock()
	got := ipForwardRefCount
	ipForwardMu.Unlock()
	if got != 0 {
		t.Fatalf("ip_forward refcount = %d after rollback, want 0", got)
	}
	gotCalls := strings.Join(*calls, "\n")
	if !strings.Contains(gotCalls, "ip link delete pvmbr0 type bridge") {
		t.Errorf("rollback did not delete the bridge:\n%s", gotCalls)
	}
	if strings.Contains(gotCalls, "iptables") {
		t.Errorf("rollback ran iptables cleanup although NAT was never set up:\n%s", gotCalls)
	}
	if strings.Contains(gotCalls, "sysctl -w") {
		t.Errorf("rollback restored ip_forward although it was never enabled:\n%s", gotCalls)
	}
}

// TestSetupBridge_ExistingBridgeFailsNoTeardown locks the re-create
// contract used by tests/47: `umlctl network create` on an existing bridge
// fails at `ip link add` (RTNETLINK File exists) and SetupBridge must NOT
// tear the pre-existing bridge down — it never owned it (bridgeCreated
// stays false), and it must not touch NAT or the ip_forward refcount.
func TestSetupBridge_ExistingBridgeFailsNoTeardown(t *testing.T) {
	resetForwardState(t)
	stubReadIPForward(t)
	calls := stubExecRun(t)
	failOn(t, "ip link add", calls) // the existing-bridge case

	err := SetupBridge("pvmbr0", "", "10.0.0.1/24")
	if err == nil {
		t.Fatal("SetupBridge must fail when the bridge already exists")
	}
	gotCalls := strings.Join(*calls, "\n")
	if strings.Contains(gotCalls, "ip link delete") {
		t.Errorf("failed re-create tore down the pre-existing bridge:\n%s", gotCalls)
	}
	if strings.Contains(gotCalls, "iptables") || strings.Contains(gotCalls, "sysctl -w") {
		t.Errorf("failed re-create touched NAT/ip_forward it never set up:\n%s", gotCalls)
	}
	ipForwardMu.Lock()
	got := ipForwardRefCount
	ipForwardMu.Unlock()
	if got != 0 {
		t.Fatalf("ip_forward refcount = %d, want 0", got)
	}
}

// TestSetupBridge_RollbackAfterRefcount asserts that a failure AFTER the
// refcount increment decrements it exactly once (the old code decremented
// twice: once via DeleteBridge and once via the ipForwardRegistered branch)
// and tears down the NAT rules for the derived subnet.
func TestSetupBridge_RollbackAfterRefcount(t *testing.T) {
	resetForwardState(t)
	stubReadIPForward(t)
	calls := stubExecRun(t)
	failOn(t, "sysctl -w", calls) // fail after refcount++

	err := SetupBridge("pvmbr1", "", "10.0.0.1/24")
	if err == nil {
		t.Fatal("SetupBridge expected to fail on injected sysctl -w error")
	}
	ipForwardMu.Lock()
	got := ipForwardRefCount
	orig := ipForwardOriginal
	ipForwardMu.Unlock()
	if got != 0 {
		t.Fatalf("ip_forward refcount = %d after rollback, want 0 (exactly-once decrement)", got)
	}
	if orig != "0" {
		t.Fatalf("ipForwardOriginal = %q, want preserved original \"0\"", orig)
	}
	gotCalls := strings.Join(*calls, "\n")
	for _, want := range []string{
		"iptables -t nat -D POSTROUTING -s 10.0.0.0/24",
		"iptables -D FORWARD -s 10.0.0.0/24 -j ACCEPT",
		"ip link delete pvmbr1 type bridge",
	} {
		if !strings.Contains(gotCalls, want) {
			t.Errorf("rollback missing %q in:\n%s", want, gotCalls)
		}
	}
	// The rollback's restore write must ALSO go through execRun so stubs
	// intercept it (the failOn stub fails it — the discard is intentional;
	// what matters is that the invocation was recorded at all).
	if !strings.Contains(gotCalls, "sysctl -w net.ipv4.ip_forward=0") {
		t.Errorf("rollback did not restore original ip_forward via execRun:\n%s", gotCalls)
	}
}

// TestDeleteBridge_EmptyGatewayIPStillTeardowns pins that DeleteBridge with
// an empty gatewayIP (the `umlctl network rm` path) still performs the link
// teardown and the refcount decrement; with the bridge gone there is simply
// no subnet to clean up, so no iptables call may happen.
func TestDeleteBridge_EmptyGatewayIPStillTeardowns(t *testing.T) {
	resetForwardState(t)
	calls := stubExecRun(t)
	if err := DeleteBridge("pvmtest-gone0", ""); err != nil {
		t.Fatalf("DeleteBridge returned error: %v", err)
	}
	got := strings.Join(*calls, "\n")
	if strings.Contains(got, "iptables") {
		t.Errorf("iptables cleanup ran for a nonexistent bridge (no subnet derivable):\n%s", got)
	}
	if !strings.Contains(got, "ip link delete pvmtest-gone0 type bridge") {
		t.Errorf("missing link teardown:\n%s", got)
	}
}

// TestDeleteBridge_RestoresIPForwardViaExecRun pins that the ip_forward
// restore write issued by DeleteBridge goes through the execRun abstraction
// (interceptable by test stubs), not a direct exec.Command the stubs cannot
// see: with a live registration (refcount 1, original "0") the teardown must
// emit the restore sysctl, drop the refcount to 0 and clear the original.
func TestDeleteBridge_RestoresIPForwardViaExecRun(t *testing.T) {
	resetForwardState(t)
	ipForwardMu.Lock()
	ipForwardRefCount = 1
	ipForwardOriginal = "0"
	ipForwardMu.Unlock()

	calls := stubExecRun(t)
	if err := DeleteBridge("pvmtest-restore0", ""); err != nil {
		t.Fatalf("DeleteBridge returned error: %v", err)
	}
	want := "sysctl -w net.ipv4.ip_forward=0"
	gotCalls := strings.Join(*calls, "\n")
	if !strings.Contains(gotCalls, want) {
		t.Errorf("missing restore write %q in:\n%s", want, gotCalls)
	}
	ipForwardMu.Lock()
	refc := ipForwardRefCount
	orig := ipForwardOriginal
	ipForwardMu.Unlock()
	if refc != 0 {
		t.Errorf("ip_forward refcount = %d after DeleteBridge, want 0", refc)
	}
	if orig != "" {
		t.Errorf("ipForwardOriginal = %q after restore, want cleared", orig)
	}
}

// TestMaskedSubnet pins the host-bit masking in bridgeSubnet's derivation:
// netlink reports interface ADDRESSES (host bits set), but teardown must use
// the canonical masked network so the -D rules match what SetupBridge added.
func TestMaskedSubnet(t *testing.T) {
	_, canon, err := net.ParseCIDR("10.200.1.5/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	// Simulate what netlink returns: IP carries the host bits.
	hostBits := &net.IPNet{IP: net.ParseIP("10.200.1.5"), Mask: canon.Mask}
	if got := maskedSubnet(hostBits); got != "10.200.1.0/24" {
		t.Errorf("maskedSubnet(10.200.1.5/24) = %q, want 10.200.1.0/24", got)
	}
	// Degenerate inputs stay "empty" (nothing addressable).
	for _, c := range []struct {
		name  string
		ipnet *net.IPNet
	}{
		{"nil", nil},
		{"nil ip", &net.IPNet{Mask: net.CIDRMask(24, 32)}},
		{"nil mask", &net.IPNet{IP: net.ParseIP("10.0.0.1")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := maskedSubnet(c.ipnet); got != "" {
				t.Errorf("maskedSubnet(%v) = %q, want empty", c.ipnet, got)
			}
		})
	}
}

// TestSetupQoS_RejectsNonRateArg pins the tc rate whitelist: only
// ^\d+[kmgKMG]bit$ may reach tc, so a crafted value cannot smuggle extra
// tc arguments.
func TestSetupQoS_RejectsNonRateArg(t *testing.T) {
	for _, bad := range []string{"10 mbit", "10mbit burst 32kbit", "", "abc", "10Gbps", "10mbit,32kbit"} {
		t.Run("rate "+strconv.Quote(bad), func(t *testing.T) {
			err := SetupQoS("tap0", bad)
			if err == nil || !strings.Contains(err.Error(), "invalid QoS rate") {
				t.Errorf("SetupQoS(rate %q) = %v, want invalid-rate error", bad, err)
			}
		})
	}
}
