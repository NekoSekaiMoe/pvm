package incident

import (
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
	act, err := c.Handle(nil, Anomaly{
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
		act, _ := c.Handle(nil, Anomaly{TaskID: "t", Severity: SeverityLow})
		if act != ActionBlock {
			t.Errorf("iter %d: expected Block, got %s", i, act)
		}
	}
	// Third low incident should escalate to Quarantine
	act, _ := c.Handle(nil, Anomaly{TaskID: "t", Severity: SeverityLow})
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
	act, _ := c.Handle(nil, Anomaly{TaskID: "t", Severity: SeverityMedium})
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
	act, err := c.Handle(nil, Anomaly{TaskID: "t", Severity: SeverityCritical})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if act != ActionTerminate {
		t.Errorf("action = %s", act)
	}
}
