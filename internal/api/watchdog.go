package api

// watchdog.go is the deadline executor (bucket-3 "ttl/refresh 只持久化无
// 执行"): a 1s sweep enforces
//
//   - E2B refresh deadlines: state.Deadline (kept alive by
//     POST /sandboxes/:id/refreshes) — expiry kills the sandbox and moves
//     the FSM to Destroy, mirroring E2B's timeout semantics;
//   - lifecycle.ttl: spec-persisted overall lifetime, expiry destroys;
//   - budget.max_network_mb: egress bytes accounted by the gateway
//     (BytesUsed, upload direction) breach reports a medium incident and
//     deny-alls the task's egress (containment, not just a log line).
//
// Budget walltime is already enforced by container.watchDeadline; token and
// micro-USD budgets stay advisory (no host-side sensor can measure them).

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"uml-container/internal/audit"
	"uml-container/internal/console"
	"uml-container/internal/metrics"
	"uml-container/internal/network/egress"
	"uml-container/internal/state"
)

var metricWatchdogKills = metrics.Counter("pvm_watchdog_kills_total", "Deadline/TTL expiries enforced", "reason")

// startWatchdog launches the sweeper (idempotent, process-wide).
func startWatchdog() {
	watchdogOnce.Do(func() {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for range t.C {
				sweepDeadlines()
			}
		}()
	})
}

// sweepDeadlines applies every expiry rule once.
func sweepDeadlines() {
	states, err := state.ListAll()
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, st := range states {
		if st == nil {
			continue
		}
		alive := st.Status == state.StatusRunning || st.Status == state.StatusSuspended ||
			st.Status == state.StatusReady || st.Status == state.StatusResuming ||
			st.Status == state.StatusPending || st.Status == state.StatusProvisioning
		if !alive {
			continue
		}

		// 1) E2B refresh deadline.
		if !st.Deadline.IsZero() && now.After(st.Deadline) {
			killTask(st.ID, st.PID, "refresh-deadline")
			continue
		}

		// One spec read per task per sweep: both TTL and budget checks below
		// consume it (loaded only after the deadline check so tasks about to
		// die skip the disk read entirely).
		s := loadTaskSpec(st.ID)

		// 2) lifecycle.ttl.
		if s != nil && s.Lifecycle.TTL != "" && st.Status == state.StatusRunning {
			if ttl, perr := time.ParseDuration(s.Lifecycle.TTL); perr == nil && ttl > 0 {
				start := st.StartedAt
				if !start.IsZero() && now.After(start.Add(ttl)) {
					killTask(st.ID, st.PID, "ttl-expired")
					continue
				}
			}
		}

		// 3) budget.max_network_mb (upload direction, gateway-accounted).
		if s != nil && s.Budget.MaxNetworkMB > 0 && st.Status == state.StatusRunning {
			if g := egressFor(st.ID); g != nil {
				limit := int64(s.Budget.MaxNetworkMB) * 1024 * 1024
				if used := g.BytesUsed(st.ID); used > limit && !budgetFlagExists(st.ID) {
					writeBudgetFlag(st.ID, used, limit)
					_, _ = reportIncident("medium", st.ID, "budget:network-exceeded",
						fmt.Sprintf("egress upload %d bytes > limit %d bytes", used, limit))
					// Containment: deny-all further egress for this task.
					g.SetPolicy(st.ID, &egress.Policy{})
				}
			}
		}
	}
}

// killTask performs the terminal transition + process kill + audit row.
func killTask(taskID string, pid int, reason string) {
	metricWatchdogKills.Inc(reason)
	if pid > 0 {
		_ = killProcessTree(pid)
	}
	console.Default().Detach(taskID)
	if st, err := state.LoadState(taskID); err == nil && st != nil {
		_ = st.Transition(state.StatusDestroy, state.ActorController, reason)
		_ = state.SaveState(taskID, st)
	}
	if l, err := audit.Open(taskID); err == nil {
		_ = l.Append(audit.Record{
			Phase:    audit.PhaseRelease,
			Subject:  taskID,
			Action:   "watchdog:kill",
			Params:   map[string]interface{}{"reason": reason, "pid": pid},
			Decision: audit.DecisionBlock,
			Reason:   "deadline enforced",
		})
		// The task is gone: stop re-verifying its ledger every sweep and drop
		// its per-task metric series so neither grows with task churn.
		l.Close()
	}
	metricTokensMinted.Delete(taskID)
	metricTokensRevoked.Delete(taskID)
	log.Printf("watchdog: task %s killed (%s)", taskID, reason)
}

func budgetFlagExists(taskID string) bool {
	dir, err := state.ContainerDir(taskID)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, ".net-budget-hit"))
	return err == nil
}

func writeBudgetFlag(taskID string, used, limit int64) {
	dir, err := state.ContainerDir(taskID)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, ".net-budget-hit"),
		[]byte(strconv.FormatInt(used, 10)+"/"+strconv.FormatInt(limit, 10)), 0o600)
}

// taskMetricsView backs GET /api/tasks/:id/metrics. Field names follow the
// OpenAPI contract (net_tx_bytes / net_rx_bytes / egress_denied_total).
func taskMetricsView(taskID string) map[string]interface{} {
	out := map[string]interface{}{
		"task":                taskID,
		"net_tx_bytes":        int64(0),
		"net_rx_bytes":        int64(0),
		"egress_denied_total": int64(0),
		"budget_net_limit":    nil,
		"deadline":            nil,
		"ttl":                 nil,
	}
	if g := egressFor(taskID); g != nil {
		out["net_tx_bytes"] = g.BytesUsed(taskID)
		out["net_rx_bytes"] = g.BytesRx(taskID)
		out["egress_denied_total"] = g.BytesDenied(taskID)
	}
	if st, err := state.LoadState(taskID); err == nil && st != nil && !st.Deadline.IsZero() {
		out["deadline"] = st.Deadline.Format(time.RFC3339)
	}
	if s := loadTaskSpec(taskID); s != nil {
		if s.Budget.MaxNetworkMB > 0 {
			out["budget_net_limit"] = s.Budget.MaxNetworkMB * 1024 * 1024
		}
		if s.Lifecycle.TTL != "" {
			out["ttl"] = s.Lifecycle.TTL
		}
	}
	return out
}

var watchdogOnce sync.Once

// registerWatchdogAPI wires the per-task metrics view.
func registerWatchdogAPI(api *echo.Group) {
	api.GET("/tasks/:id/metrics", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		if resolved, err := resolveTaskID(id); err == nil {
			id = resolved
		}
		return c.JSON(http.StatusOK, taskMetricsView(id))
	})
}
