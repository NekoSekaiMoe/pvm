package network

import "testing"

func TestBuildNetPolicyPlan(t *testing.T) {
	tests := []struct {
		name      string
		allow     []string
		deny      []string
		wantAllow int
		wantDeny  int // minimum expected
		wantErr   bool
	}{
		{
			name:      "allow and deny ranges",
			allow:     []string{"1.2.3.0/24"},
			deny:      []string{"10.0.0.0/8"},
			wantAllow: 1,
			// deny includes user deny + alwaysDenied (5)
			wantDeny: 5,
		},
		{
			name:    "invalid cidr",
			allow:   []string{"not-a-cidr"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, deny, err := BuildNetPolicyPlan(tt.allow, tt.deny)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(allow) != tt.wantAllow {
				t.Fatalf("allow len %d, want %d", len(allow), tt.wantAllow)
			}
			if len(deny) < tt.wantDeny {
				t.Fatalf("deny len %d, want >=%d", len(deny), tt.wantDeny)
			}
		})
	}
}
