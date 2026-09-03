// Package network — network policy hardening
// at single-host scale.
//
// BuildNetPolicyPlan is a pure-Go planner that runs before programming the
// eBPF whitelist_map. It validates allow/deny entries (CIDRs or bare IPs),
// deduplicates them via string sets, rejects allow entries that fall
// inside an always-denied range, appends the always-denied CIDRs to the
// deny set, caps each set at maxNetPolicyEntries, and returns both slices
// sorted for deterministic output.
package network

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

const maxNetPolicyEntries = 8192

var alwaysDeniedCIDRs = []string{
	"10.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// BuildNetPolicyPlan validates and merges user allow/deny CIDRs with the
// always-denied set. It returns the effective allow and deny slices after
// deduplication (each sorted for deterministic output), or an error if
// limits are exceeded, entries are malformed, or an allow entry falls
// inside an always-denied range.
func BuildNetPolicyPlan(allowOut, denyOut []string) (allow []string, deny []string, err error) {
	allowSet := make(map[string]struct{})
	for _, cidr := range allowOut {
		trimmed := strings.TrimSpace(cidr)
		if trimmed == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(trimmed); err != nil {
			// Accept bare IPs as /32
			if ip := net.ParseIP(trimmed); ip == nil {
				return nil, nil, fmt.Errorf("network: invalid allow CIDR/IP %q", cidr)
			}
		}
		if IsAlwaysDenied(trimmed) {
			return nil, nil, fmt.Errorf("network: allow CIDR/IP %q overlaps an always-denied range", cidr)
		}
		allowSet[trimmed] = struct{}{}
	}
	denySet := make(map[string]struct{})
	for _, cidr := range denyOut {
		trimmed := strings.TrimSpace(cidr)
		if trimmed == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(trimmed); err != nil {
			if ip := net.ParseIP(trimmed); ip == nil {
				return nil, nil, fmt.Errorf("network: invalid deny CIDR/IP %q", cidr)
			}
		}
		denySet[trimmed] = struct{}{}
	}
	// Always-denied are additive to deny.
	for _, cidr := range alwaysDeniedCIDRs {
		denySet[cidr] = struct{}{}
	}
	if len(allowSet) > maxNetPolicyEntries {
		return nil, nil, fmt.Errorf("network: allow_out exceeds %d entries (%d)", maxNetPolicyEntries, len(allowSet))
	}
	if len(denySet) > maxNetPolicyEntries {
		return nil, nil, fmt.Errorf("network: deny_out exceeds %d entries (%d)", maxNetPolicyEntries, len(denySet))
	}
	allow = make([]string, 0, len(allowSet))
	for k := range allowSet {
		allow = append(allow, k)
	}
	sort.Strings(allow)
	deny = make([]string, 0, len(denySet))
	for k := range denySet {
		deny = append(deny, k)
	}
	sort.Strings(deny)
	return allow, deny, nil
}

// IsAlwaysDenied reports whether cidr overlaps one of the always-denied
// ranges — either by falling inside one or by (partially) covering one.
// Containment alone is not enough: a broad allow such as 0.0.0.0/0 contains
// every denied range without being contained by any, and 8.0.0.0/5 merely
// straddles 10.0.0.0/8; both must count as denied overlap. cidr may be a
// CIDR or a bare IP (interpreted as a host route, /32 for IPv4 or /128 for
// IPv6); the overlap is a range check via net.IPNet.Contains rather than a
// string comparison, so narrower subnets of an always-denied range (e.g.
// 10.1.2.0/24 inside 10.0.0.0/8) are also reported as denied.
func IsAlwaysDenied(cidr string) bool {
	entry, ok := parseNetEntry(strings.TrimSpace(cidr))
	if !ok {
		return false
	}
	for _, d := range alwaysDeniedCIDRs {
		_, denied, err := net.ParseCIDR(d)
		if err != nil {
			continue // Unreachable: alwaysDeniedCIDRs are valid constants.
		}
		if cidrsOverlap(entry, denied) {
			return true
		}
	}
	return false
}

// cidrsOverlap reports whether two CIDR blocks intersect. Proper CIDR
// blocks are laminar — nested or disjoint — so it suffices to test each
// block's network address against the other; a partial-only overlap
// between two aligned power-of-two ranges cannot exist. Mismatched
// address families never overlap (Contains is false cross-family).
func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// parseNetEntry parses s as a CIDR, falling back to a bare IP interpreted
// as a host route (/32 for IPv4, /128 for IPv6). ok is false when s is
// neither a valid CIDR nor a valid IP.
func parseNetEntry(s string) (entry *net.IPNet, ok bool) {
	if _, ipNet, err := net.ParseCIDR(s); err == nil {
		return ipNet, true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, false
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, true
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, true
}
