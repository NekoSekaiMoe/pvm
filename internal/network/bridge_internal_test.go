package network

import (
	"errors"
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
