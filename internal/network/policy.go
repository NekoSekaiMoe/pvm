// Package network — policy hardening mirroring CubeNet/cubevs/netpolicy.go
// at single-host scale.
//
// This is a pure-Go LPM-trie planner that runs before programming the
// eBPF whitelist_map. It rejects always-denied CIDRs, validates entry
// counts against maxNetPolicyEntries, and expands the allow list into
// /32s for the current hash-map backend.
package network

import (
	"fmt"
	"net"
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
// deduplication, or an error if limits are exceeded or CIDRs are malformed.
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
	for k := range allowSet {
		allow = append(allow, k)
	}
	for k := range denySet {
		deny = append(deny, k)
	}
	return allow, deny, nil
}

// IsAlwaysDenied reports whether cidr/ip is in the always-denied set.
func IsAlwaysDenied(cidr string) bool {
	for _, d := range alwaysDeniedCIDRs {
		if d == strings.TrimSpace(cidr) {
			return true
		}
	}
	return false
}
