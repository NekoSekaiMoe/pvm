package policy

import (
	"testing"
)

func TestApprovalClosureUnlocksOnce(t *testing.T) {
	var consumed []string
	g := NewGateway([]Rule{{Name: "deploy", Action: ActionApprove, Effect: "prod"}}, nil)
	g.approvalCheck = func(req ToolRequest) (string, bool) {
		if req.Args["env"] == "prod" {
			return "tkt-1", true
		}
		return "", false
	}
	g.onApproved = func(id string) { consumed = append(consumed, id) }
	g.executor = SimExecutor()

	req := ToolRequest{Name: "deploy", Effect: "prod", Args: map[string]interface{}{"env": "prod"}}
	resp, err := g.Execute(req)
	if err != nil || !resp.OK {
		t.Fatalf("approved request must execute: resp=%+v err=%v", resp, err)
	}
	if len(consumed) != 1 || consumed[0] != "tkt-1" {
		t.Fatalf("ticket must be consumed once, got %v", consumed)
	}

	// Different params: no unlock.
	req2 := ToolRequest{Name: "deploy", Effect: "prod", Args: map[string]interface{}{"env": "staging"}}
	_, err = g.Execute(req2)
	if err != ErrApprovalRequired {
		t.Fatalf("non-matching params must still require approval, got %v", err)
	}
}

func TestSimExecutorMarksSimulated(t *testing.T) {
	g := NewGateway([]Rule{{Name: "read", Action: ActionAllow, Effect: "read"}}, nil)
	g.executor = SimExecutor()
	resp, err := g.Execute(ToolRequest{Name: "read", Effect: "read"})
	if err != nil || !resp.OK {
		t.Fatalf("sim exec failed: %v %+v", err, resp)
	}
	if sim, _ := resp.Result["simulated"].(bool); !sim {
		t.Fatalf("result must be marked simulated: %+v", resp.Result)
	}
}
