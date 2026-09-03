package network

import (
	"strings"
	"testing"
)

// The chain design is what makes installs idempotent and old-port rules
// self-cleaning; these tests pin the argv shape without touching iptables.
func TestTransparentL7ChainRules(t *testing.T) {
	t.Run("shape and ordering", func(t *testing.T) {
		rules := transparentL7ChainRules("t-1", "192.0.2.10", 15000)
		if len(rules) != 5 { // -N, -F, :80 REDIRECT, :443 REDIRECT, jump
			t.Fatalf("rules = %v", rules)
		}
		chain := transparentChainName("t-1")
		if got := strings.Join(rules[0], " "); got != "iptables -t nat -N "+chain {
			t.Fatalf("create = %q", got)
		}
		if got := strings.Join(rules[1], " "); got != "iptables -t nat -F "+chain {
			t.Fatalf("flush = %q", got)
		}
		for i, dp := range []string{"80", "443"} {
			want := "iptables -t nat -A " + chain + " -p tcp --dport " + dp + " -j REDIRECT --to-ports 15000"
			if got := strings.Join(rules[2+i], " "); got != want {
				t.Fatalf("redirect[%d] = %q, want %q", i, got, want)
			}
		}
		want := "iptables -t nat -A PREROUTING -s 192.0.2.10/32 -j " + chain
		if got := strings.Join(rules[4], " "); got != want {
			t.Fatalf("jump = %q, want %q", got, want)
		}
	})

	t.Run("chain name fits the xt 28-char limit and is stable", func(t *testing.T) {
		for _, id := range []string{"t-1", "some-very-long-task-identifier-with-many-characters"} {
			name := transparentChainName(id)
			if len(name) > 28 {
				t.Fatalf("chain name %q too long (%d)", name, len(name))
			}
			if name != transparentChainName(id) {
				t.Fatalf("chain name for %q not stable", id)
			}
		}
		if transparentChainName("a") == transparentChainName("b") {
			t.Fatal("distinct tasks must hash to distinct chains")
		}
	})

	t.Run("non-IPv4 guest address rejected", func(t *testing.T) {
		if transparentL7ChainRules("t-1", "not-an-ip", 15000) != nil {
			t.Fatal("bogus guest IP must yield no rules")
		}
	})

	t.Run("re-enable with a new port replaces, not duplicates", func(t *testing.T) {
		// The REDIRECT rules always target exactly ONE port inside the
		// chain and enable flushes first: two consecutive enables with
		// different ports leave exactly one :80 rule per port-set.
		oldRules := transparentL7ChainRules("t-1", "192.0.2.10", 15000)
		newRules := transparentL7ChainRules("t-1", "192.0.2.10", 16000)
		if strings.Join(oldRules[1], " ") != strings.Join(newRules[1], " ") {
			t.Fatal("flush must run on every enable")
		}
		countPort := func(rules [][]string, port string) int {
			n := 0
			for _, r := range rules {
				for _, tok := range r {
					if tok == port {
						n++
					}
				}
			}
			return n
		}
		if countPort(oldRules, "15000") != 2 || countPort(newRules, "15000") != 0 {
			t.Fatal("each enable carries only its own listener port")
		}
	})
}
