package network

// transparent_l7.go — iptables REDIRECT rules steering the guest's
// outbound TCP :80/:443 into the per-task transparent L7 gateway listener.
//
// Rules (per task, matched on the task's guest IP so co-tenant traffic on
// a shared bridge is never cross-attributed):
//
//	iptables -t nat -A PREROUTING -s <guest>/32 -p tcp --dport 80  -j REDIRECT --to-ports <port>
//	iptables -t nat -A PREROUTING -s <guest>/32 -p tcp --dport 443 -j REDIRECT --to-ports <port>
//
// Only meaningful in the BRIDGE dataplane (guest traffic traverses the
// host nat PREROUTING path); the tc plane's tap_ingress program owns its
// own steering. The rules are idempotent per (task, port) pair and are
// removed by DisableTransparentL7 / on task teardown.

import (
	"fmt"
	"net"
	"strconv"
)

// transparentPorts are the destination ports intercepted.
var transparentPorts = []int{80, 443}

// transparentL7Rules builds the argv sets for one task's REDIRECT rules.
// apply=false produces the exact -D counterparts.
func transparentL7Rules(guestIP string, port int, apply bool) [][]string {
	action := "-A"
	if !apply {
		action = "-D"
	}
	src := net.ParseIP(guestIP)
	if src == nil || src.To4() == nil {
		return nil
	}
	out := make([][]string, 0, len(transparentPorts))
	for _, dp := range transparentPorts {
		out = append(out, []string{
			"iptables", "-t", "nat", action, "PREROUTING",
			"-s", src.String() + "/32",
			"-p", "tcp", "--dport", strconv.Itoa(dp),
			"-j", "REDIRECT", "--to-ports", strconv.Itoa(port),
		})
	}
	return out
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
	for _, argv := range transparentL7Rules(guestIP, port, true) {
		if err := runIptables(argv); err != nil {
			for _, back := range transparentL7Rules(guestIP, port, false) {
				_ = runIptables(back)
			}
			return fmt.Errorf("network: transparent L7 redirect for %s: %w", taskID, err)
		}
	}
	return nil
}

// DisableTransparentL7 removes the rules (idempotent; unknown rules are a
// no-op — iptables -D of a missing rule surfaces as "Bad rule" which
// runIptables treats as success).
func DisableTransparentL7(taskID, guestIP string, port int) error {
	_ = taskID
	for _, argv := range transparentL7Rules(guestIP, port, false) {
		if err := runIptables(argv); err != nil {
			return fmt.Errorf("network: transparent L7 removal: %w", err)
		}
	}
	return nil
}
