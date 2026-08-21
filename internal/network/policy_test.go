package network

import "testing"

func TestBuildNetPolicyPlan(t *testing.T) {
	tests := []struct {
		name      string
		allow     []string
		deny      []string
		wantAllow int
		wantDeny  int // minimum expected (always-denied CIDRs are additive)
		wantErr   bool
	}{
		{
			name:      "allow and deny ranges",
			allow:     []string{"1.2.3.0/24"},
			deny:      []string{"10.0.0.0/8"},
			wantAllow: 1,
			wantDeny:  5,
		},
		{
			name:      "bare ip accepted",
			allow:     []string{"1.2.3.4"},
			wantAllow: 1,
			wantDeny:  5,
		},
		{
			name:      "blank and whitespace entries skipped",
			allow:     []string{"", "   ", "\t"},
			deny:      []string{" "},
			wantAllow: 0,
			wantDeny:  5,
		},
		{
			name:      "duplicates counted once after trimming",
			allow:     []string{"1.2.3.0/24", " 1.2.3.0/24 ", "1.2.3.0/24"},
			deny:      []string{"10.0.0.0/8", "10.0.0.0/8"},
			wantAllow: 1,
			// 10.0.0.0/8 is also an always-denied CIDR, so the deduped set is
			// exactly the 5 always-denied entries.
			wantDeny: 5,
		},
		{
			name:    "invalid allow cidr",
			allow:   []string{"not-a-cidr"},
			wantErr: true,
		},
		{
			name:    "invalid deny cidr",
			deny:    []string{"also-not-a-cidr"},
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
				t.Fatalf("allow len %d, want %d (%v)", len(allow), tt.wantAllow, allow)
			}
			if len(deny) < tt.wantDeny {
				t.Fatalf("deny len %d, want >=%d (%v)", len(deny), tt.wantDeny, deny)
			}
		})
	}
}
