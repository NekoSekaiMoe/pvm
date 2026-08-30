package api

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/labstack/echo/v4"

	"uml-container/internal/console"
	"uml-container/internal/metrics"
	"uml-container/internal/policy"
	"uml-container/internal/state"
)

// exec_runtime.go closes the Tool-Gateway execution loop (bucket-3 items):
//
//   - real executors: guest console (marker protocol) when a session exists,
//     explicit simulation backend under PVM_EXEC_SIM=1 for kernel-less hosts;
//   - approval closure: an approved, unconsumed ticket unlocks exactly one
//     execution attempt (Allow once), then is consumed;
//   - console tail endpoint for operators and the WebUI console panel.
//
// Everything is wired lazily per /api/exec (or /api/policy/:task) request so
// gateways registered by `agentpvm run` in another process still gain the
// runtime here without re-registration.

var (
	metricExecRequests  = metrics.Counter("pvm_exec_requests_total", "Tool gateway /api/exec requests", "task")
	metricExecDenied    = metrics.Counter("pvm_exec_denied_total", "Tool gateway denials", "task")
	metricExecApprovals = metrics.Counter("pvm_exec_approval_unlocks_total", "Executions unlocked by approved tickets", "task")
)

// ensureGatewayRuntime attaches the executor + approval closure to a gateway
// registered elsewhere. Idempotent; concurrency-safe: the field writes go
// through Gateway.SetRuntimeOnce, which guards nil->non-nil transitions
// with the gateway's own lock (plain field writes would race Execute).
func ensureGatewayRuntime(gw *policy.Gateway, taskID string) {
	var executor func(policy.ToolRequest) (policy.ToolResponse, error)
	if sim, consoleFn := executorBackends(taskID); sim != nil {
		executor = sim
	} else if consoleFn != nil {
		executor = consoleFn
	}
	// ApprovalCheck CLAIMS the ticket atomically (find + consume + persist
	// under the approval manager's lock) — see policy.Gateway.Execute.
	claim := func(req policy.ToolRequest) (string, bool) {
		return currentApprovals().ClaimFor(taskID, req.Name, req.Args)
	}
	onApproved := func(string) {
		// The counter's only label is "task": credit the unlock to the task
		// the gateway executes for, not to the (label-less) ticket id.
		metricExecApprovals.Inc(taskID)
	}
	gw.SetRuntimeOnce(executor, claim, onApproved)
}

// executorBackends picks the execution backend for a task: the real guest
// console when a session is live, else the explicit simulation backend.
// Both nil => gateway stays in dry-run mode (legacy behavior).
func executorBackends(taskID string) (sim func(policy.ToolRequest) (policy.ToolResponse, error), consoleFn func(policy.ToolRequest) (policy.ToolResponse, error)) {
	if os.Getenv("PVM_EXEC_SIM") == "1" {
		sim = policy.SimExecutor()
		return sim, nil
	}
	if _, err := console.Default().Get(taskID); err == nil {
		fn := policy.ConsoleExecutor(taskID, func(id string) (*console.Session, error) {
			return console.Default().Get(id)
		})
		return nil, fn
	}
	return nil, nil
}

// registerExecRuntimeExtras wires the console-tail and approval-edit routes.
func registerExecRuntimeExtras(api *echo.Group) {
	api.GET("/tasks/:id/console", func(c echo.Context) error {
		id, err := resolveTaskID(c.Param("id"))
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		sess, err := console.Default().Get(id)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		tail := string(sess.Tail(8192))
		return c.JSON(http.StatusOK, map[string]interface{}{"task": id, "tail": tail})
	})

	api.POST("/approvals/:id/edit", func(c echo.Context) error {
		var req struct {
			Params map[string]interface{} `json:"params"`
			Reason string                 `json:"reason"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		// The editor identity is the AUTHENTICATED actor, never a self-reported
		// JSON field: EditedBy feeds the audit ledger and webhooks, so letting
		// the request body name the editor would forge audit attribution.
		actor, _ := c.Get("actor").(string)
		if actor == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing authenticated actor"})
		}
		t, err := currentApprovals().Edit(c.Param("id"), req.Params, req.Reason, actor)
		if err != nil {
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, t)
	})
}

// resolveTaskID resolves a full or unique-prefix task id against the state
// root (same semantics as the E2B sandbox short-id resolution). Defined here
// until the tasks endpoints migrate onto it.
func resolveTaskID(idOrPrefix string) (string, error) {
	root := state.RootDir
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(filepath.Join(root, idOrPrefix)); err == nil && fi.IsDir() {
		return idOrPrefix, nil
	}
	var matches []string
	for _, e := range entries {
		if e.IsDir() && len(idOrPrefix) <= len(e.Name()) && e.Name()[:len(idOrPrefix)] == idOrPrefix {
			matches = append(matches, e.Name())
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", os.ErrNotExist
	default:
		return "", errAmbiguousID
	}
}

var errAmbiguousID = &ambiguousIDError{}

type ambiguousIDError struct{}

func (e *ambiguousIDError) Error() string { return "task id prefix is ambiguous" }

// initApprovalPersistence arms the global approval manager with durable
// storage and (optional) webhook notifications.
func initApprovalPersistence() {
	m := currentApprovals()
	if root := state.RootDir; root != "" {
		if err := m.EnablePersistence(filepath.Join(root, "approvals.json")); err != nil {
			// Persistence is a hardening feature: the plane keeps running
			// in-memory, but say so.
			log.Printf("approval: persistence disabled: %v", err)
		}
	}
	m.EnableWebhook(os.Getenv("PVM_APPROVAL_WEBHOOK_URL"))
}
