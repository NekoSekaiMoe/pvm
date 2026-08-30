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

// TestTestsRerunVerifier_StrictRequiresTrustedTerminalState guards the
// strict-mode hole: loose advisory keywords ("deployment passed") used to
// satisfy require_tests_passed; only trusted runner terminal states may.
func TestTestsRerunVerifier_StrictRequiresTrustedTerminalState(t *testing.T) {
	v := &TestsRerunVerifier{Strict: true}
	cases := []struct {
		name     string
		buildLog string
		want     bool
	}{
		{"prose passed is not a test run", "deployment passed\nbuild finished", false},
		{"go test summary line lacks old keywords", "ok\tpkg\t0.5s", true},
		{"go test spaces summary", "ok  pkg  0.012s", true},
		{"go test per-test + PASS lines", "=== RUN   TestX\n--- PASS: TestX (0.00s)\nPASS", true},
		{"pytest digit-led summary", "3 passed in 0.01s", true},
		{"rust libtest summary", "test result: ok. 3 passed; 0 failed; 0 ignored", true},
		{"jest Tests summary", "Tests: 3 passed, 3 total", true},
		{"empty evidence", "", false},
		{"failures still block", "--- FAIL: TestY\nFAIL", false},
		{"terminal state with nonzero failures blocks", "2 passed, 3 failed in 0.1s", false},
		{"mid-build prose with FAIL-free text", "build finished OK (fast)", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Bundle{TaskID: "t-strict", BuildLog: tc.buildLog, ClaimedOK: true}
			ok, reason := v.Verify(b)
			if ok != tc.want {
				t.Fatalf("Verify(BuildLog=%q) = (%v, %q), want ok=%v", tc.buildLog, ok, reason, tc.want)
			}
		})
	}
}

// TestTestsRerunVerifier_NonStrictAdvisoryUnchanged pins the fix contract:
// non-strict keeps the old advisory semantics — loose keywords still pass.
func TestTestsRerunVerifier_NonStrictAdvisoryUnchanged(t *testing.T) {
	v := &TestsRerunVerifier{}
	b := &Bundle{TaskID: "t-advisory", BuildLog: "deployment passed\nbuild finished", ClaimedOK: true}
	if ok, reason := v.Verify(b); !ok {
		t.Fatalf("non-strict loose keyword must stay advisory pass, got ok=false reason=%q", reason)
	}
}

// TestTestDoneRe_NoDigitFreePassed asserts the digit-led summary pattern
// excludes prose like "deployment passed" at the regex level itself.
func TestTestDoneRe_NoDigitFreePassed(t *testing.T) {
	for _, prose := range []string{"deployment passed", "checks passed by the auditor", "OK (build)"} {
		if testDoneRe.MatchString(prose) {
			t.Errorf("testDoneRe must not match prose %q", prose)
		}
	}
	for _, summary := range []string{"1 passed", "12 passed, 0 failed", "0 passed, 3 failed"} {
		if !testDoneRe.MatchString(summary) {
			t.Errorf("testDoneRe must match digit-led summary %q", summary)
		}
	}
}

// TestTestsRerunVerifier_TestCmdPathUnaffected: a configured TestCmd runs
// for real regardless of Strict — evidence regexes stay out of the way.
func TestTestsRerunVerifier_TestCmdPathUnaffected(t *testing.T) {
	v := &TestsRerunVerifier{Workspace: t.TempDir(), TestCmd: "true", Strict: true}
	b := &Bundle{TaskID: "t-cmd", ClaimedOK: true}
	if ok, reason := v.Verify(b); !ok || reason != "" {
		t.Fatalf("passing TestCmd should pass even with zero evidence, got ok=%v reason=%q", ok, reason)
	}
	v.TestCmd = "false"
	if ok, reason := v.Verify(b); ok || reason == "" {
		t.Fatalf("failing TestCmd must block, got ok=%v reason=%q", ok, reason)
	}
}
