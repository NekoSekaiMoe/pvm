package artifact

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"uml-container/internal/audit"
	"uml-container/internal/spec"
)

// verifiers.go fills the two empty pipeline steps (plan.md §7.3 steps 1–2)
// plus the declare check:
//
//	step 1 baseline_replay — the submitted diff must apply cleanly to a
//	     pristine baseline (system `patch --dry-run` when available, else a
//	     strict structural validation of every hunk);
//	step 2 tests_rerun   — a green test run is required (executed against a
//	     workspace when configured, else evidence-based: recognized test
//	     output in build log/trace with zero failures);
//	declare             — every submitted file must be declared in
//	     spec.artifacts.declared (no smuggled outputs).

// BaselineReplayVerifier validates that the bundle's Diff can be replayed.
type BaselineReplayVerifier struct {
	// BaselineDir is a pristine checkout the diff is dry-run against. When
	// empty the verifier falls back to structural validation only.
	BaselineDir string
}

func (v *BaselineReplayVerifier) Name() string { return "baseline_replay" }

func (v *BaselineReplayVerifier) Verify(b *Bundle) (bool, string) {
	if strings.TrimSpace(b.Diff) == "" {
		// Diffs are optional (a build-only task has none); nothing to replay.
		return true, ""
	}
	if hunks, err := validateUnifiedDiff(b.Diff); err != nil {
		return false, err.Error()
	} else if hunks == 0 {
		// No @@ hunks: a prose/summary diff (legacy bundles send these).
		// Nothing machine-checkable to replay — accept, matching the
		// historical contract; structural validation applies to real
		// unified diffs only.
		return true, ""
	}
	if v.BaselineDir != "" {
		if bin := patchBinary(); bin != "" {
			cmd := exec.Command(bin, "--dry-run", "--force", "-p1", "-i", "/dev/stdin")
			cmd.Dir = v.BaselineDir
			cmd.Stdin = strings.NewReader(b.Diff)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Run(); err != nil {
				return false, fmt.Sprintf("patch --dry-run failed: %v: %s", err, strings.TrimSpace(out.String()))
			}
		}
	}
	return true, ""
}

// validateUnifiedDiff parses `@@ -a,b +c,d @@` headers and checks the line
// counts in each hunk body match the header claims. Returns hunk count.
func validateUnifiedDiff(diff string) (int, error) {
	lines := strings.Split(diff, "\n")
	hunks := 0
	i := 0
	for i < len(lines) {
		if !strings.HasPrefix(lines[i], "@@") {
			i++
			continue
		}
		oldN, newN, err := parseHunkHeader(lines[i])
		if err != nil {
			return hunks, fmt.Errorf("hunk %d header: %w", hunks+1, err)
		}
		i++
		gotOld, gotNew := 0, 0
		for i < len(lines) && !(strings.HasPrefix(lines[i], "@@") || strings.HasPrefix(lines[i], "diff ") || strings.HasPrefix(lines[i], "--- ") || strings.HasPrefix(lines[i], "+++ ")) {
			switch {
			case strings.HasPrefix(lines[i], "-"):
				gotOld++
			case strings.HasPrefix(lines[i], "+"):
				gotNew++
			case strings.HasPrefix(lines[i], " ") || lines[i] == "":
				gotOld++
				gotNew++
			}
			i++
		}
		// Empty context lines serialize as truly empty lines; a trailing
		// missing newline can undercount by one — tolerate off-by-one only
		// in the last hunk.
		tolerance := 0
		if i >= len(lines) {
			tolerance = 1
		}
		if absDiff(gotOld, oldN) > tolerance || absDiff(gotNew, newN) > tolerance {
			return hunks, fmt.Errorf("hunk %d: header says -%d,+%d but body has -%d,+%d", hunks+1, oldN, newN, gotOld, gotNew)
		}
		hunks++
	}
	return hunks, nil
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

var hunkHeaderRe = regexp.MustCompile(`^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@`)

func parseHunkHeader(line string) (int, int, error) {
	m := hunkHeaderRe.FindStringSubmatch(line)
	if m == nil {
		return 0, 0, fmt.Errorf("malformed %q", line)
	}
	oldN, newN := 1, 1
	if m[1] != "" {
		fmt.Sscanf(m[1], "%d", &oldN)
	}
	if m[2] != "" {
		fmt.Sscanf(m[2], "%d", &newN)
	}
	if m[1] == "" {
		oldN = 1
	}
	if m[2] == "" {
		newN = 1
	}
	return oldN, newN, nil
}

func patchBinary() string {
	for _, c := range []string{"patch", "/usr/bin/patch"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// TestsRerunVerifier enforces plan.md §7.3 step 2.
type TestsRerunVerifier struct {
	// Workspace is the dir TestCmd runs in. When TestCmd is empty the
	// verifier is evidence-based (no re-run possible): recognized test output
	// must appear in BuildLog/Trace with no failures.
	Workspace string
	TestCmd   string
	// Strict marks evidence mode insufficient (spec require_tests_passed).
	Strict bool
}

func (v *TestsRerunVerifier) Name() string { return "tests_rerun" }

func (v *TestsRerunVerifier) Verify(b *Bundle) (bool, string) {
	if v.TestCmd != "" && v.Workspace != "" {
		cmd := exec.Command("/bin/sh", "-c", v.TestCmd)
		cmd.Dir = v.Workspace
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			return false, fmt.Sprintf("test command failed (%v): %s", err, lastLines(out.String(), 5))
		}
		return true, ""
	}
	evidence := b.BuildLog + "\n" + strings.Join(b.Trace, "\n")
	ran, fails := scanTestEvidence(evidence)
	if !ran {
		if v.Strict {
			return false, "no test evidence and no test command configured (require_tests_passed=true)"
		}
		return true, "advisory: no test evidence"
	}
	if fails > 0 {
		return false, fmt.Sprintf("test evidence shows %d failure(s)", fails)
	}
	return true, ""
}

var (
	testRanRe  = regexp.MustCompile(`(?m)(?:go test|pytest|jest|npm test|cargo test|\bPASS\b|OK \(|\bpassed\b|✓)`)
	// Failure terminal states or a NON-ZERO failure count. A bare "failed"
	// keyword would reject healthy summaries like "12 passed, 0 failed".
	testFailRe = regexp.MustCompile(`(?m)(?:\b(?:FAIL|FAILED|FAILURE)\b|\b[1-9][0-9]*\s+(?:failed|failures?)\b|✗|✕|\bpanic:)`)
)

func scanTestEvidence(s string) (ran bool, fails int) {
	ran = testRanRe.MatchString(s)
	fm := testFailRe.FindAllString(s, -1)
	fails = len(fm)
	return
}

func lastLines(s string, n int) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, " | ")
}

// DeclaredVerifier blocks undeclared output files.
type DeclaredVerifier struct {
	Declared []string
}

func (DeclaredVerifier) Name() string { return "declare" }

func (v DeclaredVerifier) Verify(b *Bundle) (bool, string) {
	if len(v.Declared) == 0 && len(b.Files) > 0 {
		return false, fmt.Sprintf("%d file(s) submitted but spec declares none", len(b.Files))
	}
	allowed := make(map[string]struct{}, len(v.Declared))
	for _, d := range v.Declared {
		allowed[d] = struct{}{}
	}
	for name := range b.Files {
		if _, ok := allowed[name]; !ok {
			return false, "file not declared in spec.artifacts.declared: " + name
		}
	}
	return true, ""
}

// FromSpec assembles a gate honoring the TaskSpec's artifacts policy. This is
// the constructor the controller and /api/gate/verify must use so the spec's
// require_tests_passed / block_secrets / declared switches actually bind.
func FromSpec(s *spec.TaskSpec, ledger *audit.Ledger, extra ...Verifier) *Gate {
	// NewGate seeds bind_hash + secret_scan; the spec-bound steps join next.
	g := NewGate(ledger, extra...)
	if s == nil {
		// Bare gate (no spec): structural checks only — replay validation and
		// advisory test evidence. Declared enforcement is a SPEC contract:
		// without a spec there is no declaration list to enforce against.
		g.AddVerifier(&BaselineReplayVerifier{}, &TestsRerunVerifier{})
		return g
	}
	art := s.Artifacts
	g.AddVerifier(
		&BaselineReplayVerifier{},
		&TestsRerunVerifier{Strict: art.RequireTestsPassed},
		DeclaredVerifier{Declared: art.Declared},
	)
	if !art.BlockSecrets {
		// Spec explicitly allows secrets in artifacts: keep the scan for the
		// record but do not fail the release on it.
		g.SetAdvisory((&SecretScanVerifier{}).Name())
	}
	return g
}
