package artifact

import (
	"strings"
	"testing"

	"uml-container/internal/spec"
)

func TestBaselineReplayStructuralValidation(t *testing.T) {
	v := &BaselineReplayVerifier{}

	good := "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n line1\n-old\n+new\n"
	if ok, reason := v.Verify(&Bundle{Diff: good}); !ok {
		t.Fatalf("well-formed diff must pass: %s", reason)
	}

	badCounts := "@@ -1,5 +1,2 @@\n a\n b\n"
	if ok, _ := v.Verify(&Bundle{Diff: badCounts}); ok {
		t.Fatal("hunk header/body mismatch must fail")
	}

	garbage := "@@ not a hunk @@\n"
	if ok, _ := v.Verify(&Bundle{Diff: garbage}); ok {
		t.Fatal("malformed hunk header must fail")
	}

	// Empty diff: optional, nothing to replay.
	if ok, reason := v.Verify(&Bundle{Diff: ""}); !ok || reason != "" {
		t.Fatalf("empty diff must pass silently, got ok=%v reason=%q", ok, reason)
	}
}

func TestTestsRerunEvidenceModes(t *testing.T) {
	v := &TestsRerunVerifier{}

	// Evidence-based: green run.
	if ok, reason := v.Verify(&Bundle{BuildLog: "$ go test ./...\nok  pkg  0.1s\nPASS"}); !ok {
		t.Fatalf("green evidence must pass: %s", reason)
	}
	// Evidence-based: failure markers.
	if ok, _ := v.Verify(&Bundle{BuildLog: "pytest\nFAILED test_a.py - AssertionError"}); ok {
		t.Fatal("failure evidence must fail")
	}
	// No evidence, advisory mode passes.
	if ok, _ := v.Verify(&Bundle{BuildLog: "built artifact"}); !ok {
		t.Fatal("advisory mode must pass without evidence")
	}
	// No evidence, strict mode fails.
	strict := &TestsRerunVerifier{Strict: true}
	if ok, reason := strict.Verify(&Bundle{BuildLog: "built artifact"}); ok {
		t.Fatal("strict mode must fail without evidence")
	} else if !strings.Contains(reason, "require_tests_passed") {
		t.Fatalf("reason must cite the spec switch: %s", reason)
	}
	// Configured command, failing.
	cmd := &TestsRerunVerifier{Workspace: t.TempDir(), TestCmd: "exit 3"}
	if ok, _ := cmd.Verify(&Bundle{}); ok {
		t.Fatal("failing test command must fail the gate")
	}
	// Configured command, passing.
	cmdOK := &TestsRerunVerifier{Workspace: t.TempDir(), TestCmd: "echo ok"}
	if ok, reason := cmdOK.Verify(&Bundle{}); !ok {
		t.Fatalf("passing test command must pass: %s", reason)
	}
}

func TestDeclaredVerifier(t *testing.T) {
	v := DeclaredVerifier{Declared: []string{"report.md"}}
	if ok, _ := v.Verify(&Bundle{Files: map[string][]byte{"report.md": nil}}); !ok {
		t.Fatal("declared file must pass")
	}
	if ok, reason := v.Verify(&Bundle{Files: map[string][]byte{"secret.env": nil}}); ok {
		t.Fatal("undeclared file must fail")
	} else if !strings.Contains(reason, "secret.env") {
		t.Fatalf("reason must name the file: %s", reason)
	}
	empty := DeclaredVerifier{}
	if ok, _ := empty.Verify(&Bundle{Files: map[string][]byte{"x": nil}}); ok {
		t.Fatal("files without any declaration must fail")
	}
}

func TestFromSpecBindsSwitches(t *testing.T) {
	s := &spec.TaskSpec{}
	s.Artifacts.BlockSecrets = false
	s.Artifacts.RequireTestsPassed = true
	s.Artifacts.Declared = []string{"report.md"}
	g := FromSpec(s, nil)

	// Secret in an undeclared file: declare check fails (blocking), secret
	// scan is advisory (recorded, not in Reasons).
	v := g.Verify(&Bundle{
		TaskID:   "t-gate",
		Files:    map[string][]byte{"report.md": []byte("clean")},
		BuildLog: "no tests here",
	})
	if v.Passed {
		t.Fatal("strict tests + no evidence must fail the gate")
	}
	joined := strings.Join(v.Reasons, "; ")
	if !strings.Contains(joined, "tests_rerun") {
		t.Fatalf("tests_rerun must be a blocking reason: %s", joined)
	}

	// Advisory secret scan: secret present but block_secrets=false.
	v2 := g.Verify(&Bundle{
		TaskID:   "t-gate",
		Files:    map[string][]byte{"report.md": []byte("aws_secret_access_key=" + strings.Repeat("x", 40))},
		BuildLog: "go test ./...\nok\nPASS",
	})
	if !v2.Passed {
		t.Fatalf("advisory secret scan must not block: %v", v2.Reasons)
	}
	if !strings.Contains(v2.Step["secret_scan"], "advisory") {
		t.Fatalf("advisory outcome must be recorded in step map: %v", v2.Step)
	}

	// BlockSecrets=true flips it to blocking.
	s.Artifacts.BlockSecrets = true
	g3 := FromSpec(s, nil)
	v3 := g3.Verify(&Bundle{
		TaskID:   "t-gate",
		Files:    map[string][]byte{"report.md": []byte("aws_secret_access_key=" + strings.Repeat("x", 40))},
		BuildLog: "go test ./...\nok\nPASS",
	})
	if v3.Passed {
		t.Fatal("blocking secret scan must fail on leaked secret")
	}
}

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
