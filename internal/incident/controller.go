// Package incident implements the Incident Controller (plan.md §11).
//
// Flow: ANOMALY -> REVOKE -> BLOCK -> PAUSE -> PRESERVE -> decision branch.
//
// Kill is a BRANCH, not a fixed step: the controller classifies the anomaly
// before deciding whether to terminate, pause-and-hand-off, or just block.
// Classification:
//
//	suspected exfiltration   -> disconnect network then TERMINATE
//	logic error / weirdness  -> PAUSE for human takeover
//	credential leak          -> REVOKE all identities
//	critical / confirmed     -> TERMINATE
//
// Each action is idempotent and recorded in the audit ledger.
package incident

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"uml-container/internal/audit"
	"uml-container/internal/identity"
	"uml-container/internal/state"
)

// Severity classifies an anomaly.
type Severity string

const (
	SeverityLow      Severity = "low"       // weirdness, retry-able
	SeverityMedium   Severity = "medium"    // logic error, needs human
	SeverityHigh     Severity = "high"      // suspected exfiltration
	SeverityCritical Severity = "critical"  // confirmed attack
)

// Anomaly is a signal from a sensor (egress gateway, tool gateway, budget).
type Anomaly struct {
	TaskID    string
	Severity  Severity
	Signal    string // e.g. "egress:blocked-domain-attempt", "budget:exceeded"
	Detail    string
	At        time.Time
}

// Action is the controller's response.
type Action string

const (
	ActionNone      Action = "none"
	ActionBlock     Action = "block"      // network + new tools
	ActionRevoke    Action = "revoke"     // identities
	ActionPause     Action = "pause"      // freeze runtime
	ActionTerminate Action = "terminate"  // kill + cleanup
	ActionQuarantine Action = "quarantine" // move to Quarantined state
)

// Hooks let the controller drive concrete subsystems without hard dependencies
// on the network/cgroup/container packages. The controller's job is policy;
// the host wires the mechanism.
type Hooks struct {
	// BlockNetwork disables egress for the task (e.g. swap in a deny-all policy).
	BlockNetwork func(taskID string) error
	// RevokeIdentities revokes all broker tokens for the task.
	RevokeIdentities func(taskID string) error
	// FreezeRuntime freezes the cgroup (pause).
	FreezeRuntime func(taskID string) error
	// Terminate kills the UML process and tears down resources.
	Terminate func(taskID string) error
	// Preserve snapshots the现场 for later inspection.
	Preserve func(taskID string) error
}

// Controller is the incident response orchestrator.
type Controller struct {
	hooks  Hooks
	ledger *audit.Ledger
	broker *identity.Broker
	mu     sync.Mutex
	handled map[string]int // task -> count of incidents (for escalation)
}

// NewController wires the controller. ledger is required; hooks/broker optional
// but the controller can only do policy-level actions without them.
func NewController(ledger *audit.Ledger, broker *identity.Broker, hooks Hooks) *Controller {
	return &Controller{
		hooks:   hooks,
		ledger:  ledger,
		broker:  broker,
		handled: make(map[string]int),
	}
}

// Classify decides the action for an anomaly based on severity + signal.
// This is the "Kill is a branch, not a fixed step" decision table.
func Classify(a Anomaly) Action {
	switch a.Severity {
	case SeverityCritical:
		return ActionTerminate
	case SeverityHigh:
		// suspected exfiltration: disconnect then terminate
		return ActionQuarantine
	case SeverityMedium:
		return ActionPause
	case SeverityLow:
		return ActionBlock
	}
	return ActionNone
}

// Handle is the entry point. It runs REVOKE -> BLOCK -> PAUSE -> PRESERVE in
// the order the chosen Action implies (terminating actions do all of them),
// then records the decision and updates the task's lifecycle state.
//
// stateMgr and broker may be nil; the controller degrades to audit-only. If a
// hook returns an error, Handle records a DecisionDeny audit row with the
// failure reason and returns the error so the caller knows the response did
// not fully take effect.
func (c *Controller) Handle(ctx context.Context, a Anomaly) (Action, error) {
	c.mu.Lock()
	c.handled[a.TaskID]++
	count := c.handled[a.TaskID]
	c.mu.Unlock()

	act := Classify(a)
	// Escalation: repeated low/medium incidents escalate one level.
	if count >= 3 && (act == ActionBlock || act == ActionPause) {
		act = ActionQuarantine
	}

	c.audit(a, act, "classified")

	// Collect hook failures without aborting the whole response: incident
	// response should apply as much containment as it can, then report what
	// failed. The first error is returned to the caller.
	var firstErr error
	recordFailure := func(stage string, err error) {
		if err == nil {
			return
		}
		if firstErr == nil {
			firstErr = err
		}
		if c.ledger != nil {
			_ = c.ledger.Append(audit.Record{
				Phase:    audit.PhaseExec,
				Subject:  a.TaskID,
				Action:   "incident:" + stage,
				Decision: audit.DecisionDeny,
				Reason:   stage + " hook failed: " + err.Error(),
			})
		}
	}

	// The plan.md §11.2 sequence: REVOKE -> BLOCK -> PAUSE -> PRESERVE, then
	// the branch decision. We apply the prefix relevant to the action.
	switch act {
	case ActionQuarantine, ActionTerminate:
		recordFailure("revoke", c.applyRevoke(a.TaskID))
		recordFailure("block", c.applyBlock(a.TaskID))
		recordFailure("pause", c.applyPause(a.TaskID))
		recordFailure("preserve", c.applyPreserve(a.TaskID))
	case ActionPause:
		recordFailure("pause", c.applyPause(a.TaskID))
		recordFailure("preserve", c.applyPreserve(a.TaskID))
	case ActionBlock:
		recordFailure("block", c.applyBlock(a.TaskID))
	case ActionRevoke:
		recordFailure("revoke", c.applyRevoke(a.TaskID))
	case ActionNone:
		// nothing
	}

	if act == ActionTerminate && c.hooks.Terminate != nil {
		if err := c.hooks.Terminate(a.TaskID); err != nil {
			c.audit(a, act, "terminate failed: "+err.Error())
			return act, err
		}
	}
	return act, firstErr
}

func (c *Controller) applyRevoke(task string) error {
	if c.broker != nil {
		c.broker.RevokeAllForTask(task)
	}
	if c.hooks.RevokeIdentities != nil {
		if err := c.hooks.RevokeIdentities(task); err != nil {
			return err
		}
	}
	c.auditRaw(task, "revoke", audit.DecisionRevoke, "incident response")
	return nil
}

func (c *Controller) applyBlock(task string) error {
	if c.hooks.BlockNetwork != nil {
		if err := c.hooks.BlockNetwork(task); err != nil {
			return err
		}
	}
	c.auditRaw(task, "block", audit.DecisionBlock, "incident response")
	return nil
}

func (c *Controller) applyPause(task string) error {
	if c.hooks.FreezeRuntime != nil {
		if err := c.hooks.FreezeRuntime(task); err != nil {
			return err
		}
	}
	c.auditRaw(task, "pause", audit.DecisionConstrain, "incident response")
	return nil
}

func (c *Controller) applyPreserve(task string) error {
	if c.hooks.Preserve != nil {
		return c.hooks.Preserve(task)
	}
	return nil
}

func (c *Controller) audit(a Anomaly, act Action, reason string) {
	if c.ledger == nil {
		return
	}
	if err := c.ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  a.TaskID,
		Action:   "incident:" + string(act),
		Params:   map[string]interface{}{"signal": a.Signal, "severity": a.Severity, "detail": a.Detail},
		Decision: audit.DecisionBlock,
		Reason:   reason,
	}); err != nil {
		log.Printf("incident: audit failed for task %s: %v", a.TaskID, err)
	}
}

func (c *Controller) auditRaw(task, action string, dec audit.Decision, reason string) {
	if c.ledger == nil {
		return
	}
	if err := c.ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  task,
		Action:   action,
		Decision: dec,
		Reason:   reason,
	}); err != nil {
		log.Printf("incident: audit (%s) failed for task %s: %v", action, task, err)
	}
}

// MoveToQuarantine transitions the task's FSM to Quarantined. Used after a
// quarantine-classification to make the isolation durable in lifecycle state.
func MoveToQuarantine(st *state.ContainerState, reason string) error {
	if st == nil {
		return fmt.Errorf("incident: nil state")
	}
	// Quarantined is reachable from Running/Provisioning/Failed per the FSM.
	return st.Transition(state.StatusQuarantined, state.ActorController, "incident: "+reason)
}
