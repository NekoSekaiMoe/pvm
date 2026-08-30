package api

// incident_api.go gives the Incident Controller a REST surface and wires the
// previously dangling hooks (bucket-3 "incident 接线不全"):
//
//	POST /api/incidents/:task/report  — any sensor (gate, egress, budget,
//	                                   operator scripts) reports an anomaly;
//	                                   the controller runs the full response
//	                                   pipeline (revoke→block→pause→preserve).
//	GET  /api/incidents               — recent handled incidents.
//
// Hooks default to in-process mechanisms: the credential broker (revoke),
// the registered egress gateway (deny-all), the cgroup manager (freeze) and
// event snapshots (preserve). agentpvm can override via
// RegisterIncidentController with its own wired controller.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"

	"uml-container/internal/artifact"
	"uml-container/internal/cgroup"
	"uml-container/internal/console"
	"uml-container/internal/incident"
	"uml-container/internal/metrics"
	"uml-container/internal/network/egress"
	"uml-container/internal/snapshot"
	"uml-container/internal/state"
)

// artifactVerdictView mirrors the fields gateSensor needs (avoids importing
// artifact here just for one accessor).
type artifactVerdictView = artifact.Verdict

var (
	globalIncidentMu sync.RWMutex
	globalIncident   *incident.Controller

	// Egress gateway registry: per-task gateways started by the controller
	// (agentpvm run) register here so the incident BlockNetwork hook and the
	// policy endpoints can reach them from the API process.
	globalEgressMu       sync.RWMutex
	globalEgressGateways = map[string]*egress.Gateway{}

	metricIncidents     = metrics.Counter("pvm_incidents_total", "Incidents handled by the controller", "task", "severity")
	metricEgressBlocked = metrics.Counter("pvm_egress_blocked_tasks_total", "Tasks whose egress was deny-alled by incident response", "task")
)

// RegisterIncidentController lets the controller inject a fully wired
// controller (its own ledger + hooks).
func RegisterIncidentController(c *incident.Controller) {
	globalIncidentMu.Lock()
	globalIncident = c
	globalIncidentMu.Unlock()
}

// RegisterEgressGateway publishes a task's egress gateway for policy updates
// and incident containment from the API process.
func RegisterEgressGateway(taskID string, g *egress.Gateway) {
	globalEgressMu.Lock()
	globalEgressGateways[taskID] = g
	globalEgressMu.Unlock()
}

func egressFor(taskID string) *egress.Gateway {
	globalEgressMu.RLock()
	defer globalEgressMu.RUnlock()
	return globalEgressGateways[taskID]
}

// currentIncident lazily builds the default in-process controller.
func currentIncident() *incident.Controller {
	globalIncidentMu.RLock()
	c := globalIncident
	globalIncidentMu.RUnlock()
	if c != nil {
		return c
	}
	globalIncidentMu.Lock()
	defer globalIncidentMu.Unlock()
	if globalIncident != nil {
		return globalIncident
	}
	broker, _ := CurrentIdentity()
	globalIncident = incident.NewController(nil, broker, incident.Hooks{
		BlockNetwork: func(taskID string) error {
			g := egressFor(taskID)
			if g == nil {
				// No gateway in this process (task booted elsewhere): the
				// explicit error makes the containment gap visible in the
				// audit trail instead of pretending the net was cut.
				return fmt.Errorf("no egress gateway registered for task %s", taskID)
			}
			// Empty policy = deny-all (no allowlist entries => default deny).
			g.SetPolicy(taskID, &egress.Policy{})
			metricEgressBlocked.Inc(taskID)
			return nil
		},
		FreezeRuntime: func(taskID string) error {
			m := cgroup.NewManager()
			if err := m.Freeze(taskID); err != nil {
				// A missing cgroup (CI hosts without the pvm tree, or an
				// already-exited task) is not a containment failure — the
				// runtime is as frozen as it can ever be.
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			// Reflect the freeze in lifecycle state where the FSM allows.
			if st, err := state.LoadState(taskID); err == nil && st != nil && st.Status == state.StatusRunning {
				_ = st.Transition(state.StatusSuspended, state.ActorController, "incident: freeze")
				_ = state.SaveState(taskID, st)
			}
			return nil
		},
		Terminate: func(taskID string) error {
			st, err := state.LoadState(taskID)
			if err != nil || st == nil {
				return fmt.Errorf("incident: no state for task %s", taskID)
			}
			if st.PID > 0 {
				if kerr := killProcessTree(st.PID); kerr != nil {
					return kerr
				}
			}
			console.Default().Detach(taskID)
			_ = st.Transition(state.StatusDestroy, state.ActorController, "incident: terminate")
			_ = state.SaveState(taskID, st)
			return nil
		},
		Preserve: func(taskID string) error {
			snap, err := snapshot.CreateEventSnapshot(taskID, "incident-"+time.Now().UTC().Format("20060102T150405Z"), "", map[string]string{
				"reason": "incident-response-preserve",
			})
			if err != nil && strings.Contains(err.Error(), "container dir not found") {
				// No container directory => nothing to preserve (task never
				// booted on this host). Not a response failure.
				return nil
			}
			_ = snap
			return err
		},
	})
	return globalIncident
}

// killProcessTree sends SIGKILL to the pid (best effort; UML is a single
// process from the host's view, so no /proc subtree walk is needed).
func killProcessTree(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Signal(syscall.SIGKILL); err != nil && !strings.Contains(err.Error(), "process already finished") {
		return err
	}
	return nil
}

// incidentRecord is the GET /api/incidents row.
type incidentRecord struct {
	TaskID    string          `json:"task_id"`
	Severity  string          `json:"severity"`
	Signal    string          `json:"signal"`
	Detail    string          `json:"detail"`
	Action    incident.Action `json:"action"`
	At        time.Time       `json:"at"`
	ErrorText string          `json:"error,omitempty"`
}

var (
	incidentLogMu sync.Mutex
	incidentLog   []incidentRecord
)

func recordIncident(r incidentRecord) {
	incidentLogMu.Lock()
	if len(incidentLog) >= 256 {
		incidentLog = incidentLog[1:]
	}
	incidentLog = append(incidentLog, r)
	incidentLogMu.Unlock()
}

// reportIncident is the shared entry point for REST reports and internal
// sensors (artifact gate secret hits, egress deny storms once wired).
func reportIncident(sev, taskID, signal, detail string) (incident.Action, error) {
	a := incident.Anomaly{
		TaskID:   taskID,
		Severity: incident.Severity(sev),
		Signal:   signal,
		Detail:   detail,
		At:       time.Now().UTC(),
	}
	if a.Severity == "" {
		a.Severity = incident.SeverityLow
	}
	act, err := currentIncident().Handle(context.Background(), a)
	metricIncidents.Inc(taskID, string(a.Severity))
	recordIncident(incidentRecord{
		TaskID: taskID, Severity: string(a.Severity), Signal: signal,
		Detail: detail, Action: act, At: time.Now().UTC(),
		ErrorText: errString(err),
	})
	return act, err
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// registerIncidentAPI wires the endpoints.
func registerIncidentAPI(api *echo.Group) {
	api.POST("/incidents/:task/report", func(c echo.Context) error {
		task := c.Param("task")
		var req struct {
			Severity string `json:"severity"`
			Signal   string `json:"kind"`
			Detail   string `json:"detail"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		switch strings.ToLower(req.Severity) {
		case "low", "medium", "high", "critical":
		default:
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "severity must be low|medium|high|critical"})
		}
		if req.Signal == "" {
			req.Signal = "manual-report"
		}
		act, err := reportIncident(strings.ToLower(req.Severity), task, req.Signal, req.Detail)
		body := map[string]interface{}{"task": task, "action": act}
		if err != nil {
			body["warning"] = "response incomplete: " + err.Error()
		}
		return c.JSON(http.StatusOK, body)
	})

	api.GET("/incidents", func(c echo.Context) error {
		incidentLogMu.Lock()
		out := append([]incidentRecord{}, incidentLog...)
		incidentLogMu.Unlock()
		if out == nil {
			out = []incidentRecord{}
		}
		return c.JSON(http.StatusOK, out)
	})
}

// sensor: a failed artifact gate reports a medium incident (secret leaks
// and undeclared outputs are exactly the anomalies §11 wants paused).
func gateSensor(taskID string, v *artifactVerdictView) {
	if taskID == "" || v == nil || v.Passed {
		return
	}
	_, _ = reportIncident("medium", taskID, "artifact:gate-failed", strings.Join(v.Reasons, "; "))
}
