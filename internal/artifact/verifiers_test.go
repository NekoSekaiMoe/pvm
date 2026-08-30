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
