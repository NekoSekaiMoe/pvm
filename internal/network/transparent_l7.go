package network

// transparent_l7.go — iptables REDIRECT rules steering the guest's
// outbound TCP :80/:443 into the per-task transparent L7 gateway listener.
//
// Rules (per task, matched on the task's guest IP so co-tenant traffic on
// a shared bridge is never cross-attributed):
//
//	iptables -t nat -N PVML7-<hash(task)>            # per-task chain
//	iptables -t nat -F PVML7-<hash(task)>            # wipe stale rules first
//	iptables -t nat -A PVML7-<hash(task)> -p tcp --dport 80  -j REDIRECT --to-ports <port>
//	iptables -t nat -A PVML7-<hash(task)> -p tcp --dport 443 -j REDIRECT --to-ports <port>
//	iptables -t nat -A PREROUTING -s <guest>/32 -j PVML7-<hash(task)>
//
// The dedicated per-task chain is what makes the install IDEMPOTENT and
// restart-safe: enable flushes the chain before filling it, so repeated
// enables never append duplicate rules and a re-enable with a NEW listener
// port can never be shadowed by leftover rules pointing at the OLD (dead)
// port — the historical flat `-A PREROUTING` rules accumulated duplicates
// because `-D` removes only one copy at a time.
//
// Only meaningful in the BRIDGE dataplane (guest traffic traverses the
// host nat PREROUTING path); the tc plane's tap_ingress program owns its
// own steering. Rules are removed by DisableTransparentL7 / on task
// teardown.

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strconv"
)

// transparentPorts are the destination ports intercepted.
var transparentPorts = []int{80, 443}

// transparentChainName derives a short, stable iptables chain name for a
// task. xt chain names are limited to 28 characters and task ids are not
// constrained, so the id is hashed into the name.
func transparentChainName(taskID string) string {
	sum := sha256.Sum256([]byte("pvm-tl7:" + taskID))
	return fmt.Sprintf("PVML7-%x", sum[:8]) // 6 + 16 = 22 chars
}

// transparentL7ChainRules builds the argv sets for one task's redirect:
// (0) create the chain, (1) flush it, (2..) the per-port REDIRECT rules
// inside the chain, (last) the PREROUTING jump matched on the guest IP.
// Pure function — unit-tested without touching the host.
func transparentL7ChainRules(taskID, guestIP string, port int) [][]string {
	src := net.ParseIP(guestIP)
	if src == nil || src.To4() == nil {
		return nil
	}
	chain := transparentChainName(taskID)
	out := [][]string{
		{"iptables", "-t", "nat", "-N", chain},
		{"iptables", "-t", "nat", "-F", chain},
	}
	for _, dp := range transparentPorts {
		out = append(out, []string{
			"iptables", "-t", "nat", "-A", chain,
			"-p", "tcp", "--dport", strconv.Itoa(dp),
			"-j", "REDIRECT", "--to-ports", strconv.Itoa(port),
		})
	}
	out = append(out, []string{
		"iptables", "-t", "nat", "-A", "PREROUTING",
		"-s", src.String() + "/32",
		"-j", chain,
	})
	return out
}

// transparentL7JumpRule is the PREROUTING jump (apply=false produces the
// -D counterpart used by runIptablesDelete's -C probe).
func transparentL7JumpRule(taskID, guestIP string, apply bool) []string {
	action := "-A"
	if !apply {
		action = "-D"
	}
	src := net.ParseIP(guestIP)
	if src == nil || src.To4() == nil {
		return nil
	}
	return []string{
		"iptables", "-t", "nat", action, "PREROUTING",
		"-s", src.String() + "/32",
		"-j", transparentChainName(taskID),
	}
}

// runIptablesEnsure appends a rule only when the equivalent -C probe says
// it is absent (append-only idempotency).
func runIptablesEnsure(argv []string) error {
	check := append([]string(nil), argv...)
	for i, tok := range check {
		if tok == "-A" {
			check[i] = "-C"
			break
		}
	}
	if err := runIptables(check); err == nil {
		return nil // already installed
	}
	return runIptables(argv)
}

// EnableTransparentL7 installs the REDIRECT rules for one task. Fails if
// iptables rejects the rules (no root/CAP_NET_ADMIN); callers degrade with
// an audited warning — the explicit-proxy path keeps working.
func EnableTransparentL7(taskID, guestIP string, port int) error {
	if taskID == "" {
		return fmt.Errorf("network: transparent L7 requires a task id")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("network: transparent L7 port %d out of range", port)
	}
	rules := transparentL7ChainRules(taskID, guestIP, port)
	if rules == nil {
		return fmt.Errorf("network: transparent L7 requires an IPv4 guest address, got %q", guestIP)
	}
	// -N on an existing chain only errors with "already exists" — the
	// flush below fails loudly if the chain genuinely cannot be managed.
	_ = runIptables(rules[0])
	for _, argv := range rules[1 : len(rules)-1] {
		if err := runIptables(argv); err != nil {
			_ = DisableTransparentL7(taskID, guestIP, port)
			return fmt.Errorf("network: transparent L7 redirect for %s: %w", taskID, err)
		}
	}
	if err := runIptablesEnsure(rules[len(rules)-1]); err != nil {
		_ = DisableTransparentL7(taskID, guestIP, port)
		return fmt.Errorf("network: transparent L7 redirect for %s: %w", taskID, err)
	}
	return nil
}

// DisableTransparentL7 removes the jump, flushes and deletes the per-task
// chain (idempotent; unknown rules are a no-op — iptables -D of a missing
// rule surfaces as "Bad rule" which runIptablesDelete treats as success).
// The port parameter is kept for caller compatibility: the rules live in
// the per-task chain, so teardown needs no port.
func DisableTransparentL7(taskID, guestIP string, port int) error {
	_ = port
	jump := transparentL7JumpRule(taskID, guestIP, false)
	if jump == nil {
		return nil
	}
	if err := runIptablesDelete(jump); err != nil {
		return fmt.Errorf("network: transparent L7 removal: %w", err)
	}
	chain := []string{"iptables", "-t", "nat"}
	_ = runIptables(append(append([]string(nil), chain...), "-F", transparentChainName(taskID)))
	_ = runIptables(append(append([]string(nil), chain...), "-X", transparentChainName(taskID)))
	return nil
}
