package state

import "testing"

// TestFSM_AllIllegalEdges walks every (from, to) pair and asserts only the
// documented edges pass. This catches accidental table-broadening regressions.
func TestFSM_AllIllegalEdges(t *testing.T) {
	all := []Status{
		StatusPending, StatusProvisioning, StatusReady, StatusRunning,
		StatusSuspended, StatusResuming, StatusReview, StatusCompleted,
		StatusFailed, StatusQuarantined, StatusDestroy, StatusStopped, StatusExited,
	}
	allowedSet := map[Status]map[Status]bool{}
	for from, tos := range allowed {
		allowedSet[from] = map[Status]bool{}
		for _, to := range tos {
			allowedSet[from][to] = true
		}
	}

	for _, from := range all {
		for _, to := range all {
			if from == to {
				continue // idempotent, always allowed
			}
			got := canTransition(from, to)
			want := allowedSet[from][to]
			if got != want {
				t.Errorf("canTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
			// also: terminal states allow nothing
			if from.Terminal() && got {
				t.Errorf("terminal %s allowed transition to %s", from, to)
			}
		}
	}
}

func TestFSM_AllLegalEdgesExecute(t *testing.T) {
	// Every documented legal edge must actually succeed via Transition() and
	// append exactly one audit row.
	for from, tos := range allowed {
		for _, to := range tos {
			s := &ContainerState{ID: "x", Status: from}
			before := len(s.Transitions)
			if err := s.Transition(to, ActorController, "legal-edge-test"); err != nil {
				t.Errorf("legal edge %s -> %s failed: %v", from, to, err)
			}
			if s.Status != to {
				t.Errorf("after %s -> %s, status = %s", from, to, s.Status)
			}
			if len(s.Transitions) != before+1 {
				t.Errorf("edge %s -> %s did not append exactly one record", from, to)
			}
		}
	}
}

func TestFSM_RetryResetsFromFailed(t *testing.T) {
	// The Failed -> Provisioning edge is what makes auto-retry possible.
	s := &ContainerState{ID: "x", Status: StatusFailed}
	if err := s.Transition(StatusProvisioning, ActorController, "retry"); err != nil {
		t.Fatalf("retry edge failed: %v", err)
	}
}

func TestFSM_QuarantineReachableFromActiveStates(t *testing.T) {
	// Anomaly isolation must be reachable from every "live" state — if a task
	// is mid-flight and goes rogue, we must be able to yank it to Quarantined.
	for _, from := range []Status{StatusProvisioning, StatusRunning, StatusFailed} {
		if !canTransition(from, StatusQuarantined) {
			t.Errorf("Quarantined must be reachable from %s", from)
		}
	}
}

func TestFSM_DestroyReachableFromEverywhere(t *testing.T) {
	// Destroy is the cleanup terminal; it must be reachable from any active
	// state (so a controller can always tear down).
	for from := range allowed {
		if !canTransition(from, StatusDestroy) {
			t.Errorf("Destroy must be reachable from %s", from)
		}
	}
}
