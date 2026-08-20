package network

import "testing"

func TestBuildNetPolicyPlan(t *testing.T) {
	allow, deny, err := BuildNetPolicyPlan([]string{"1.2.3.0/24"}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(allow) != 1 {
		t.Fatalf("allow len %d, want 1", len(allow))
	}
	// deny should include user deny + alwaysDenied (5)
	if len(deny) < 5 {
		t.Fatalf("deny len %d, want >=5", len(deny))
	}
}

func TestBuildNetPolicyPlan_InvalidCIDR(t *testing.T) {
	_, _, err := BuildNetPolicyPlan([]string{"not-a-cidr"}, nil)
	if err == nil {
		t.Fatalf("expected error for invalid CIDR")
	}
}
