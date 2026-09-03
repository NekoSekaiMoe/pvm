package egress

// metrics.go — Prometheus handles for the L7 gateway. The registry lives
// in internal/metrics; the counter is declared here (next to its only
// writer, SetPolicy) and scraped through /metrics.

import "uml-container/internal/metrics"

// metricsPolicyUpdates counts runtime policy updates per task. Every bump
// also invalidates the task's live tunnels (see SetPolicy), so the counter
// doubles as a "connections were re-judged" signal.
var metricsPolicyUpdates = metrics.Counter("pvm_egress_policy_updates_total",
	"Egress policy updates (each invalidates live tunnels)", "task")
