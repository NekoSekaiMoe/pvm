package network

import (
	"os/exec"
	"strings"
	"testing"
)

// toolingPresent returns true if every listed binary is on PATH.
func toolingPresent(bins ...string) bool {
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			return false
		}
	}
	return true
}

func TestCreateTap_RequiresIproute2(t *testing.T) {
	if !toolingPresent("ip") {
		t.Skip("ip not available; skipping (requires iproute2 and/or root)")
	}
	// Use an obviously invalid name; `ip` rejects overly-long / bad names.
	err := CreateTap("definitely-not-a-real-device-!@#")
	if err == nil {
		t.Fatalf("expected error creating an invalid tap, got nil")
	}
	if !strings.Contains(err.Error(), "failed to create tap") {
		t.Errorf("unexpected error shape: %v", err)
	}
}

func TestSetupQoS_RequiresTc(t *testing.T) {
	if !toolingPresent("tc") {
		t.Skip("tc not available; skipping (requires iproute2-tc and/or root)")
	}
	err := SetupQoS("definitely-not-a-real-device-!@#", "10mbit")
	if err == nil {
		t.Fatalf("expected error setting QoS on a non-existent device, got nil")
	}
	if !strings.Contains(err.Error(), "failed to setup QoS") {
		t.Errorf("unexpected error shape: %v", err)
	}
}

func TestSetupBridge_InvalidCIDR(t *testing.T) {
	// SetupBridge needs root + ip to even create the bridge, so if those are
	// missing we can still assert the input-validation order: a syntactically
	// invalid gatewayIP must be reported. Depending on env this is caught
	// either at the bridge-creation step or at the ParseCIDR step.
	if !toolingPresent("ip") {
		t.Skip("ip not available; skipping")
	}
	err := SetupBridge("pvmtest-bad-cidr", "", "not-a-cidr")
	if err == nil {
		t.Fatalf("expected error for invalid gatewayIP, got nil")
	}
}
