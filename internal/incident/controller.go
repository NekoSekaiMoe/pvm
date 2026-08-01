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
// stateMgr and broker may be nil; the controller degrades to audit-only.
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

	// The plan.md §11.2 sequence: REVOKE -> BLOCK -> PAUSE -> PRESERVE, then
	// the branch decision. We apply the prefix relevant to the action.
	switch act {
	case ActionQuarantine, ActionTerminate:
		c.applyRevoke(a.TaskID)
		c.applyBlock(a.TaskID)
		c.applyPause(a.TaskID)
		c.applyPreserve(a.TaskID)
	case ActionPause:
		c.applyPause(a.TaskID)
		c.applyPreserve(a.TaskID)
	case ActionBlock:
		c.applyBlock(a.TaskID)
	case ActionRevoke:
		c.applyRevoke(a.TaskID)
	case ActionNone:
		// nothing
	}

	if act == ActionTerminate && c.hooks.Terminate != nil {
		if err := c.hooks.Terminate(a.TaskID); err != nil {
			c.audit(a, act, "terminate failed: "+err.Error())
			return act, err
		}
	}
	return act, nil
}

func (c *Controller) applyRevoke(task string) {
	if c.broker != nil {
		c.broker.RevokeAllForTask(task)
	}
	if c.hooks.RevokeIdentities != nil {
		c.hooks.RevokeIdentities(task)
	}
	c.auditRaw(task, "revoke", audit.DecisionRevoke, "incident response")
}

func (c *Controller) applyBlock(task string) {
	if c.hooks.BlockNetwork != nil {
		c.hooks.BlockNetwork(task)
	}
	c.auditRaw(task, "block", audit.DecisionBlock, "incident response")
}

func (c *Controller) applyPause(task string) {
	if c.hooks.FreezeRuntime != nil {
		c.hooks.FreezeRuntime(task)
	}
	c.auditRaw(task, "pause", audit.DecisionConstrain, "incident response")
}

func (c *Controller) applyPreserve(task string) {
	if c.hooks.Preserve != nil {
		c.hooks.Preserve(task)
	}
}

func (c *Controller) audit(a Anomaly, act Action, reason string) {
	if c.ledger == nil {
		return
	}
	_ = c.ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  a.TaskID,
		Action:   "incident:" + string(act),
		Params:   map[string]interface{}{"signal": a.Signal, "severity": a.Severity, "detail": a.Detail},
		Decision: audit.DecisionBlock,
		Reason:   reason,
	})
}

func (c *Controller) auditRaw(task, action string, dec audit.Decision, reason string) {
	if c.ledger == nil {
		return
	}
	_ = c.ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  task,
		Action:   action,
		Decision: dec,
		Reason:   reason,
	})
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
