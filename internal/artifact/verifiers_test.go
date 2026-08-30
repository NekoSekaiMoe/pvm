package artifact

import (
	"strings"
	"testing"
)

// TestScanTestEvidence_IgnoresZeroFailed guards the PR #22 review bug: the
// failure regex must not treat the bare word "failed" in a HEALTHY summary
// ("12 passed, 0 failed") as a failure.
func TestScanTestEvidence_IgnoresZeroFailed(t *testing.T) {
	healthy := []string{
		"12 passed, 0 failed in 3.21s",       // pytest
		"--- PASS: TestX\nok  pkg  0.012s",   // go test
		"Tests: 3 passed, 0 failed, 0 total", // jest-ish
	}
	for _, log := range healthy {
		ran, fails := scanTestEvidence(log)
		if !ran {
			t.Errorf("healthy log %q should count as ran", log)
		}
		if fails != 0 {
			t.Errorf("healthy log %q reported %d failures, want 0", log, fails)
		}
	}
}

func TestScanTestEvidence_CatchesRealFailures(t *testing.T) {
	broken := []string{
		"--- FAIL: TestY\nFAIL\nFAIL\tpkg\t0.5s",
		"11 failed, 2 passed in 0.05s",
		"panic: runtime error: index out of range",
		"✗ something broke",
	}
	for _, log := range broken {
		_, fails := scanTestEvidence(log)
		if fails == 0 {
			t.Errorf("broken log %q reported 0 failures, want > 0", log)
		}
	}
}

// TestTestsRerunVerifier_EvidenceMode covers the evidence path end-to-end:
// healthy summaries must release, failing evidence must block.
func TestTestsRerunVerifier_EvidenceMode(t *testing.T) {
	v := &TestsRerunVerifier{}
	b := &Bundle{TaskID: "t-verdict", ClaimedOK: true}

	if ok, reason := v.Verify(b); !ok || !strings.Contains(reason, "advisory") {
		t.Fatalf("no evidence + non-strict must be advisory pass, got ok=%v reason=%q", ok, reason)
	}

	b.BuildLog = "12 passed, 0 failed in 1.0s"
	if ok, _ := v.Verify(b); !ok {
		t.Fatal("healthy summary must pass the verifier")
	}

	b.BuildLog = "3 failed, 9 passed in 1.0s"
	if ok, _ := v.Verify(b); ok {
		t.Fatal("failing summary must fail the verifier")
	}
}
