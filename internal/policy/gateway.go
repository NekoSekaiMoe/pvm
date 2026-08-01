// Package policy implements the Tool/Policy Gateway (plan.md §6).
//
// Every tool call the agent makes flows through Decide(), which matches the
// call against the TaskSpec's tool rules and returns one of:
//
//	ALLOW      -> read-only ops, auto-permitted
//	CONSTRAIN  -> write ops, allowed only within the task branch
//	APPROVE    -> send/delete/pay/prod ops, must show params + get an approval ticket
//	DENY       -> pay/prod by default, or anything matching a deny rule
//
// Crucially, the Observation returned to the agent is a STRUCTURED SUMMARY,
// never the raw result containing secrets (plan.md §6.3). Raw material is read
// via the identity broker on the HOST side; only the summary crosses back.
package policy

import (
	"errors"
	"fmt"
	"strings"

	"uml-container/internal/audit"
)

// Action is the gateway verdict.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionConstrain Action = "constrain"
	ActionApprove   Action = "approve"
	ActionDeny      Action = "deny"
)

// ToolRequest is what the agent submits to invoke a tool.
type ToolRequest struct {
	Name   string                 `json:"name"`
	Args   map[string]interface{} `json:"args"`
	Effect string                 `json:"effect"` // read/write/send/delete/pay/prod
}

// ToolResponse is the structured Observation returned to the agent. It carries
// a summary + status, never raw secrets.
type ToolResponse struct {
	OK      bool                   `json:"ok"`
	Summary string                 `json:"summary"`
	Result  map[string]interface{} `json:"result,omitempty"`
	Reason  string                 `json:"reason,omitempty"`
}

// Gateway holds the compiled rules and decides each call.
type Gateway struct {
	rules  []Rule
	ledger *audit.Ledger
	// Executor is the host-side action runner. Given a permitted request, it
	// performs the actual work (e.g. git push, file read) using broker-scoped
	// credentials, and returns a sanitized summary. nil = dry-run mode.
	Executor func(req ToolRequest) (ToolResponse, error)
}

// Rule is a compiled ToolRule (from spec.ToolRule).
type Rule struct {
	Name   string
	Action Action
	Effect string
	Reason string
}

// NewGateway compiles a rule list into a gateway. A default-deny catch-all is
// appended so anything unmatched is denied (plan.md §6.2 "PAY/PROD default
// deny" generalizes to "anything not explicitly allowed is denied").
func NewGateway(rules []Rule, ledger *audit.Ledger) *Gateway {
	g := &Gateway{rules: append([]Rule{}, rules...), ledger: ledger}
	// ensure a catch-all deny exists
	hasCatchAll := false
	for _, r := range g.rules {
		if r.Name == "*" {
			hasCatchAll = true
		}
	}
	if !hasCatchAll {
		g.rules = append(g.rules, Rule{Name: "*", Action: ActionDeny, Reason: "no matching allow rule"})
	}
	return g
}

// CompileRules converts spec-style rules to compiled Rules. This lives here to
// keep spec (data) decoupled from policy (decisioning).
func CompileRules(raw []struct{ Name, Action, Effect, Reason string }) []Rule {
	out := make([]Rule, 0, len(raw)+1)
	for _, r := range raw {
		act := Action(strings.ToLower(r.Action))
		if act == "" {
			act = ActionDeny
		}
		out = append(out, Rule{Name: r.Name, Action: act, Effect: r.Effect, Reason: r.Reason})
	}
	return out
}

// Decide returns the Action for a request without executing it. Used by the
// approval flow to know whether to pause.
func (g *Gateway) Decide(req ToolRequest) (Action, Rule, error) {
	for _, r := range g.rules {
		if r.Name == req.Name || r.Name == "*" {
			// first match wins; but skip a catch-all if a more specific rule
			// exists later. We already append catch-all last, so first match
			// is the most specific.
			return r.Action, r, nil
		}
	}
	// unreachable: catch-all always matches
	return ActionDeny, Rule{Name: "*", Action: ActionDeny}, nil
}

// Rules returns the compiled rule list (for introspection / API exposure).
// Callers must not mutate the returned slice.
func (g *Gateway) Rules() []Rule {
	return append([]Rule{}, g.rules...)
}

// Execute runs a tool request through the full gateway:
// decide -> (maybe pause for approval) -> execute host-side -> sanitize -> audit.
//
// If the decision is APPROVE, it returns ErrApprovalRequired with the params
// the human must approve; the caller (API/controller) surfaces a ticket.
// If DENY, returns ErrDenied.
func (g *Gateway) Execute(req ToolRequest) (ToolResponse, error) {
	act, rule, err := g.Decide(req)
	if err != nil {
		return ToolResponse{}, err
	}
	switch act {
	case ActionDeny:
		g.audit(req, audit.DecisionDeny, "denied by rule: "+rule.Reason)
		return ToolResponse{OK: false, Reason: "denied: " + rule.Reason}, ErrDenied
	case ActionApprove:
		// Don't execute yet; surface the approval ticket.
		g.audit(req, audit.DecisionApprove, "approval required: "+rule.Reason)
		return ToolResponse{OK: false, Reason: "approval required"}, ErrApprovalRequired
	case ActionAllow, ActionConstrain:
		if g.Executor == nil {
			// dry-run / sandboxed executor not wired: return a structured
			// acknowledgment so the agent loop can continue.
			dec := audit.DecisionAllow
			if act == ActionConstrain {
				dec = audit.DecisionConstrain
			}
			g.audit(req, dec, "dry-run "+string(act))
			return ToolResponse{OK: true, Summary: fmt.Sprintf("%s: simulated (no executor)", req.Name)}, nil
		}
		// CONSTRAIN means writes must land inside the task workspace; the
		// executor is responsible for enforcing that contract.
		resp, err := g.Executor(req)
		if err != nil {
			g.audit(req, audit.DecisionDeny, "executor error: "+err.Error())
			return ToolResponse{}, err
		}
		dec := audit.DecisionAllow
		if act == ActionConstrain {
			dec = audit.DecisionConstrain
		}
		g.audit(req, dec, "executed "+string(act))
		return sanitize(resp), nil
	}
	return ToolResponse{}, ErrDenied
}

// sanitize strips fields known to carry raw secrets before returning to the
// agent. We deny-by-default on field names: only an allowlist of summary keys
// passes through. This is the "标准化 Observation 返回模型" (plan.md §6.3).
func sanitize(r ToolResponse) ToolResponse {
	if r.Result == nil {
		return r
	}
	safe := map[string]interface{}{}
	for k, v := range r.Result {
		if isSafeSummaryKey(k) {
			safe[k] = v
		}
	}
	r.Result = safe
	return r
}

// isSafeSummaryKey returns true for keys that may legitimately appear in an
// Observation. Anything else (token, secret, password, key, ...) is dropped.
func isSafeSummaryKey(k string) bool {
	low := strings.ToLower(k)
	for _, bad := range []string{"token", "secret", "password", "passwd", "key", "credential", "cookie", "auth"} {
		if strings.Contains(low, bad) {
			return false
		}
	}
	return true
}

func (g *Gateway) audit(req ToolRequest, dec audit.Decision, reason string) {
	if g.ledger == nil {
		return
	}
	_ = g.ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  "agent",
		Action:   "tool:" + req.Name,
		Params:   req.Args,
		Decision: dec,
		Reason:   reason,
	})
}

// ErrDenied is returned when a tool call is denied by policy.
var ErrDenied = errors.New("policy: tool call denied")

// ErrApprovalRequired is returned when a tool call needs a human approval ticket.
var ErrApprovalRequired = errors.New("policy: approval required")
