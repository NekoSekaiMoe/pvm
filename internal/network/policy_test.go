package network

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func TestBuildNetPolicyPlan(t *testing.T) {
	tests := []struct {
		name      string
		allow     []string
		deny      []string
		wantAllow int
		wantDeny  int // exact: deduped user deny ∪ the 5 always-denied CIDRs
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
			// 10.0.0.0/8 is itself an always-denied CIDR, so the deduped set
			// must be EXACTLY the 5 always-denied entries — a dedup failure
			// that double-counts would produce 6.
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
		{
			name:    "allow exactly always-denied cidr rejected",
			allow:   []string{"169.254.0.0/16"},
			wantErr: true,
		},
		{
			name:    "allow narrower subnet of always-denied rejected",
			allow:   []string{"10.1.2.0/24"},
			wantErr: true,
		},
		{
			name:    "allow bare ip inside always-denied rejected",
			allow:   []string{"192.168.1.10"},
			wantErr: true,
		},
		{
			// Regression: 0.0.0.0/0 COVERS every always-denied range without
			// being contained by any of them — containment-only checking used
			// to let it through.
			name:    "allow 0.0.0.0/0 covering all denied ranges rejected",
			allow:   []string{"0.0.0.0/0"},
			wantErr: true,
		},
		{
			// Regression: 8.0.0.0/5 (8.0.0.0–15.255.255.255) straddles
			// 10.0.0.0/8 — overlaps it without being contained by it.
			name:    "allow 8.0.0.0/5 straddling 10.0.0.0/8 rejected",
			allow:   []string{"8.0.0.0/5"},
			wantErr: true,
		},
		{
			name:      "deny narrower than always-denied still merged",
			allow:     []string{"8.8.8.0/24"},
			deny:      []string{"10.5.0.0/16"},
			wantAllow: 1,
			// user deny is NOT rejected for overlapping; it adds one entry
			// on top of the 5 always-denied CIDRs.
			wantDeny: 6,
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
			if len(deny) != tt.wantDeny {
				t.Fatalf("deny len %d, want exactly %d (%v)", len(deny), tt.wantDeny, deny)
			}
		})
	}
}

func TestIsAlwaysDenied(t *testing.T) {
	// alwaysDeniedCIDRs = 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
	// 172.16.0.0/12, 192.168.0.0/16.
	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{name: "exact always-denied cidr", cidr: "10.0.0.0/8", want: true},
		{name: "narrower subnet inside 10/8", cidr: "10.200.0.0/14", want: true},
		{name: "private /16 inside 172.16/12", cidr: "172.20.0.0/16", want: true},
		{name: "bare ip inside 172.16/12", cidr: "172.31.255.254", want: true},
		{name: "loopback address", cidr: "127.0.0.1", want: true},
		{name: "metadata address", cidr: "169.254.169.254", want: true},
		{name: "bare ip inside 192.168/16", cidr: "192.168.0.1", want: true},
		{name: "public cidr", cidr: "8.8.8.0/24", want: false},
		{name: "public bare ip", cidr: "1.2.3.4", want: false},
		{name: "adjacent public range not contained", cidr: "11.0.0.0/8", want: false},
		{name: "everything-range covers all denied ranges", cidr: "0.0.0.0/0", want: true},
		{name: "straddling range overlaps 10/8 without containment", cidr: "8.0.0.0/5", want: true},
		{name: "straddling range overlaps 192.168/16 edge", cidr: "192.160.0.0/12", want: true},
		{name: "invalid entry", cidr: "not-a-cidr", want: false},
		{name: "empty entry", cidr: "", want: false},
		{name: "whitespace trimmed before match", cidr: "  10.0.0.0/8  ", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAlwaysDenied(tt.cidr); got != tt.want {
				t.Fatalf("IsAlwaysDenied(%q) = %v, want %v", tt.cidr, got, tt.want)
			}
		})
	}
}

func TestBuildNetPolicyPlanEntryLimit(t *testing.T) {
	// distinctCIDRs returns n distinct public /24s (e.g. 1.<hi>.<lo>.0/24).
	distinctCIDRs := func(prefix string, n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("%s%d.%d.0/24", prefix, i/256, i%256))
		}
		return out
	}
	t.Run("allow exactly at limit succeeds", func(t *testing.T) {
		allow, _, err := BuildNetPolicyPlan(distinctCIDRs("1.", maxNetPolicyEntries), nil)
		if err != nil {
			t.Fatalf("unexpected error at %d entries: %v", maxNetPolicyEntries, err)
		}
		if len(allow) != maxNetPolicyEntries {
			t.Fatalf("allow len %d, want %d", len(allow), maxNetPolicyEntries)
		}
	})
	t.Run("allow over limit errors", func(t *testing.T) {
		if _, _, err := BuildNetPolicyPlan(distinctCIDRs("1.", maxNetPolicyEntries+1), nil); err == nil {
			t.Fatalf("expected error for %d allow entries, got nil", maxNetPolicyEntries+1)
		}
	})
	t.Run("deny over limit errors", func(t *testing.T) {
		// User denies plus the always-denied CIDRs must exceed the cap.
		n := maxNetPolicyEntries - len(alwaysDeniedCIDRs) + 1
		if _, _, err := BuildNetPolicyPlan(nil, distinctCIDRs("2.", n)); err == nil {
			t.Fatalf("expected error for %d deny entries (+%d always-denied), got nil", n, len(alwaysDeniedCIDRs))
		}
	})
}

func TestBuildNetPolicyPlanSortedOutput(t *testing.T) {
	allow, deny, err := BuildNetPolicyPlan(
		[]string{"9.9.9.9", "  8.8.8.8", "1.2.3.0/24"},
		[]string{"11.0.0.0/8", "10.5.0.0/16"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantAllow := []string{"1.2.3.0/24", "8.8.8.8", "9.9.9.9"}
	if !sort.StringsAreSorted(allow) || !reflect.DeepEqual(allow, wantAllow) {
		t.Fatalf("allow = %v, want sorted %v", allow, wantAllow)
	}
	wantDeny := append(append([]string{}, alwaysDeniedCIDRs...), "10.5.0.0/16", "11.0.0.0/8")
	sort.Strings(wantDeny)
	if !sort.StringsAreSorted(deny) || !reflect.DeepEqual(deny, wantDeny) {
		t.Fatalf("deny = %v, want sorted %v", deny, wantDeny)
	}
}
