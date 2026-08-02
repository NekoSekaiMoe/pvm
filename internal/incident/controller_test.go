package incident

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"uml-container/internal/audit"
)

func tmpLedger(t *testing.T) *audit.Ledger {
	t.Helper()
	dir := t.TempDir()
	audit.LedgerRoot = dir
	l, _ := audit.Open("incident-test")
	return l
}

func TestClassify(t *testing.T) {
	cases := []struct {
		sev  Severity
		want Action
	}{
		{SeverityLow, ActionBlock},
		{SeverityMedium, ActionPause},
		{SeverityHigh, ActionQuarantine},
		{SeverityCritical, ActionTerminate},
	}
	for _, c := range cases {
		got := Classify(Anomaly{Severity: c.sev})
		if got != c.want {
			t.Errorf("Classify(%s) = %s, want %s", c.sev, got, c.want)
		}
	}
}

func TestHandle_CriticalTerminates(t *testing.T) {
	terminated := false
	c := NewController(tmpLedger(t), nil, Hooks{
		Terminate: func(string) error { terminated = true; return nil },
		RevokeIdentities: func(string) error { return nil },
		BlockNetwork:     func(string) error { return nil },
		FreezeRuntime:    func(string) error { return nil },
		Preserve:         func(string) error { return nil },
	})
	act, err := c.Handle(context.Background(), Anomaly{
		TaskID: "t1", Severity: SeverityCritical, Signal: "confirmed-exfil", At: time.Now(),
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if act != ActionTerminate {
		t.Errorf("action = %s, want terminate", act)
	}
	if !terminated {
		t.Error("terminate hook not called for critical")
	}
}

func TestHandle_Escalation(t *testing.T) {
	c := NewController(tmpLedger(t), nil, Hooks{})
	// Two low-severity incidents -> Block
	for i := 0; i < 2; i++ {
		act, _ := c.Handle(context.Background(), Anomaly{TaskID: "t", Severity: SeverityLow})
		if act != ActionBlock {
			t.Errorf("iter %d: expected Block, got %s", i, act)
		}
	}
	// Third low incident should escalate to Quarantine
	act, _ := c.Handle(context.Background(), Anomaly{TaskID: "t", Severity: SeverityLow})
	if act != ActionQuarantine {
		t.Errorf("escalation: expected Quarantine, got %s", act)
	}
}

func TestHandle_PauseRunsPreserve(t *testing.T) {
	preserved := false
	frozen := false
	c := NewController(tmpLedger(t), nil, Hooks{
		FreezeRuntime: func(string) error { frozen = true; return nil },
		Preserve:      func(string) error { preserved = true; return nil },
	})
	act, _ := c.Handle(context.Background(), Anomaly{TaskID: "t", Severity: SeverityMedium})
	if act != ActionPause {
		t.Fatalf("action = %s", act)
	}
	if !frozen {
		t.Error("freeze not called on pause")
	}
	if !preserved {
		t.Error("preserve not called on pause (现场 must be kept)")
	}
}

func TestHandle_NoHooksDoesNotPanic(t *testing.T) {
	c := NewController(tmpLedger(t), nil, Hooks{})
	act, err := c.Handle(context.Background(), Anomaly{TaskID: "t", Severity: SeverityCritical})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if act != ActionTerminate {
		t.Errorf("action = %s", act)
	}
}

// TestHandle_HookErrorPropagates verifies that a failing hook is reported via
// the returned error (and an audit deny row), instead of being silently
// swallowed. Pre-fix, applyRevoke/applyBlock/applyPause discarded the error
// and Handle always returned nil, so incident response could silently no-op.
func TestHandle_HookErrorPropagates(t *testing.T) {
	blockErr := errors.New("netns swap failed")
	c := NewController(tmpLedger(t), nil, Hooks{
		BlockNetwork: func(string) error { return blockErr },
	})
	// SeverityLow -> ActionBlock, which calls applyBlock -> BlockNetwork.
	_, err := c.Handle(context.Background(), Anomaly{TaskID: "t", Severity: SeverityLow, Signal: "weird"})
	if !errors.Is(err, blockErr) {
		t.Errorf("expected hook error to propagate, got %v", err)
	}
	// And the failure must be recorded as DecisionDeny in the audit ledger so
	// operators can see the response didn't take effect.
	recs, _ := c.ledger.ReadAll()
	foundDeny := false
	for _, r := range recs {
		if r.Decision == audit.DecisionDeny && strings.Contains(r.Reason, "block hook failed") {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Errorf("expected a DecisionDeny audit row for the failed hook; got %+v", recs)
	}
}

// TestHandle_StillAppliesRemainingActionsOnPartialFailure ensures that even
// when one hook fails, the other containment actions still run. Incident
// response should be best-effort: a failed pause (cgroup busy) does not mean
// we skip the subsequent Preserve step, and the first hook error is returned.
func TestHandle_StillAppliesRemainingActionsOnPartialFailure(t *testing.T) {
	blockCalled := false
	pauseCalled := false
	preserveCalled := false
	pauseErr := errors.New("cgroup busy")
	c := NewController(tmpLedger(t), nil, Hooks{
		BlockNetwork:  func(string) error { blockCalled = true; return nil },
		FreezeRuntime: func(string) error { pauseCalled = true; return pauseErr },
		Preserve:      func(string) error { preserveCalled = true; return nil },
	})
	// Critical -> Quarantine-class sequence: revoke+block+pause+preserve. The
	// pause hook returns an error; Preserve must STILL run, and Handle must
	// surface the pause error.
	_, err := c.Handle(context.Background(), Anomaly{TaskID: "t", Severity: SeverityCritical})
	if !errors.Is(err, pauseErr) {
		t.Errorf("expected pause hook error to propagate, got %v", err)
	}
	if !blockCalled {
		t.Error("block skipped after a pause hook failure")
	}
	if !pauseCalled {
		t.Error("pause hook not invoked")
	}
	if !preserveCalled {
		t.Error("preserve hook skipped after pause failure (best-effort containment broken)")
	}
}
