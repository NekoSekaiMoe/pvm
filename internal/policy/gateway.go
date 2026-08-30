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
	"sync"

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
	// executor is the host-side action runner. Given a permitted request, it
	// performs the actual work (e.g. git push, file read) using broker-scoped
	// credentials, and returns a sanitized summary. nil = dry-run mode.
	// Unexported so callers outside the package cannot bypass SetRuntimeOnce
	// (and its locking); it is written only via SetRuntimeOnce.
	executor func(req ToolRequest) (ToolResponse, error)

	// approvalCheck closes the approval loop: when an APPROVE-class request
	// arrives, the gateway asks for a CLAIM on an approved ticket matching
	// (task, tool, params). The implementation must find, consume AND durably
	// persist atomically (see approval.Manager.ClaimFor) so one ticket can
	// never unlock two concurrent executions. A successful claim consumes
	// the ticket immediately; nil = approval never auto-clears.
	// Unexported: written only via SetRuntimeOnce (see executor).
	approvalCheck func(req ToolRequest) (ticketID string, approved bool)
	// onApproved is invoked right after a ticket is claimed (before the
	// execution attempt). It is a notification/metric hook — consumption is
	// the claim's job, not this callback's.
	// Unexported: written only via SetRuntimeOnce (see executor).
	onApproved func(ticketID string)

	// runtimeMu guards the three hook fields above: /api/exec wires them
	// lazily while other requests may already be executing through the
	// gateway, so nil->non-nil transitions still need synchronization (a
	// plain field write is a data race against Execute's reads).
	runtimeMu sync.Mutex
}

// SetRuntimeOnce atomically fills only the STILL-NIL hook fields. Hooks are
// never replaced once set, so the first caller's wiring wins.
func (g *Gateway) SetRuntimeOnce(executor func(ToolRequest) (ToolResponse, error), approvalCheck func(ToolRequest) (string, bool), onApproved func(string)) {
	g.runtimeMu.Lock()
	defer g.runtimeMu.Unlock()
	if g.executor == nil && executor != nil {
		g.executor = executor
	}
	if g.approvalCheck == nil && approvalCheck != nil {
		g.approvalCheck = approvalCheck
	}
	if g.onApproved == nil && onApproved != nil {
		g.onApproved = onApproved
	}
}

// runtimeHooks returns a consistent snapshot of the hook fields.
func (g *Gateway) runtimeHooks() (func(ToolRequest) (ToolResponse, error), func(ToolRequest) (string, bool), func(string)) {
	g.runtimeMu.Lock()
	defer g.runtimeMu.Unlock()
	return g.executor, g.approvalCheck, g.onApproved
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
			// first match wins; but a rule with a non-empty Effect constrains the
			// match: a scoped rule authorizes ONLY that Effect. This is the
			// PAY/PROD default-deny guarantee (plan.md §6.2): a rule that only
			// authorizes "read" must not satisfy a "pay" request, and a request
			// that carries no Effect must not be satisfied by a scoped rule at
			// all (it falls through to later rules or the default denial).
			//
			// The earlier condition "r.Effect != "" && req.Effect != "" && ..."
			// was wrong: when req.Effect was empty it short-circuited the
			// inequality check, so scoped rules matched effect-less requests.
			if r.Effect != "" && r.Effect != req.Effect {
				continue
			}
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
	executor, approvalCheck, onApproved := g.runtimeHooks()
	switch act {
	case ActionDeny:
		g.audit(req, audit.DecisionDeny, "denied by rule: "+rule.Reason)
		return ToolResponse{OK: false, Reason: "denied: " + rule.Reason}, ErrDenied
	case ActionApprove:
		// Approval closure: an approved, unconsumed ticket for exactly this
		// (task, tool, params) unlocks ONE execution attempt. The claim (find
		// + consume + persist, atomically inside the approval manager)
		// happens BEFORE the executor runs: two concurrent requests cannot
		// both claim the same ticket, and a crash mid-execution cannot
		// resurrect it (plan.md §10 "Allow once"). Without a matching ticket
		// the request still pauses behind ErrApprovalRequired.
		if approvalCheck != nil {
			if ticketID, ok := approvalCheck(req); ok {
				if onApproved != nil {
					onApproved(ticketID)
				}
				g.audit(req, audit.DecisionAllow, "unlocked by approved ticket "+ticketID)
				if executor == nil {
					return ToolResponse{OK: true, Summary: fmt.Sprintf("%s: simulated (no executor), unlocked by ticket %s", req.Name, ticketID)}, nil
				}
				resp, err := executor(req)
				if err != nil {
					g.audit(req, audit.DecisionDeny, "executor error (approved): "+err.Error())
					return ToolResponse{}, err
				}
				return sanitize(resp), nil
			}
		}
		// Don't execute yet; surface the approval ticket.
		g.audit(req, audit.DecisionApprove, "approval required: "+rule.Reason)
		return ToolResponse{OK: false, Reason: "approval required"}, ErrApprovalRequired
	case ActionAllow, ActionConstrain:
		if executor == nil {
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
		resp, err := executor(req)
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
// passes through, and the scrub is applied RECURSIVELY so nested maps/slices
// cannot smuggle a secret-named field past the top level. This is the
// "标准化 Observation 返回模型" (plan.md §6.3).
func sanitize(r ToolResponse) ToolResponse {
	// Summary/Reason are free-text; the executor may accidentally echo a
	// secret into them. Always apply the regex-based redactor, even when the
	// Result map is nil, so prose can't leak a token.
	r.Summary = audit.RedactSecrets(r.Summary)
	r.Reason = audit.RedactSecrets(r.Reason)
	if r.Result == nil {
		return r
	}
	r.Result = audit.ScrubValue(r.Result).(map[string]interface{})
	return r
}

func (g *Gateway) audit(req ToolRequest, dec audit.Decision, reason string) {
	if g.ledger == nil {
		return
	}
	// Redact before persisting: tool args and error text often carry tokens,
	// and the ledger is append-only on disk. ScrubValue recursively drops
	// secret-named keys and RedactSecrets masks pattern hits in prose. The
	// ledger's own redactor (audit.Ledger.Append) applies the same scrub as a
	// second line of defense; both are idempotent.
	safeArgs := audit.ScrubValue(req.Args)
	_ = g.ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  "agent",
		Action:   "tool:" + req.Name,
		Params:   safeArgs,
		Decision: dec,
		Reason:   audit.RedactSecrets(reason),
	})
}

// ErrDenied is returned when a tool call is denied by policy.
var ErrDenied = errors.New("policy: tool call denied")

// ErrApprovalRequired is returned when a tool call needs a human approval ticket.
var ErrApprovalRequired = errors.New("policy: approval required")
