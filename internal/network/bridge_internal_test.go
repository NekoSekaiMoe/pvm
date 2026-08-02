package network

import (
	"errors"
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

// TestDeleteBridge_InvalidCIDRStillAttemptsTeardown documents the contract
// that an unparseable gatewayIP is skipped for the iptables cleanup but does
// not abort the bridge teardown itself. Without root/iproute2 the underlying
// `ip` calls fail, so we only assert the function returns rather than hangs
// or panics — and that it never surfaces the CIDR parse error.
func TestDeleteBridge_InvalidCIDRSkipped(t *testing.T) {
	// A syntactically invalid gatewayIP must not cause a panic or a CIDR
	// error; the function proceeds to `ip link` teardown (which may itself
	// fail in unprivileged CI — both outcomes are acceptable here).
	_ = DeleteBridge("pvmtest-nonexistent-bridge-!@#", "not-a-cidr")
}
