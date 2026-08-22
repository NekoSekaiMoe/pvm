package main

// Unit tests for the pure helpers in cmd/agentpvm. Subcommand wiring is
// covered end-to-end by tests/06_test_cli_smoke.sh; here we pin down the
// config-resolution precedence, the task-id validator, the spec->policy
// translation, and the built-in safe-default TaskSpec.

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uml-container/internal/spec"
)

// chdir switches the working directory for the duration of a test.
// (t.Chdir does not exist at the module's language version, go 1.22.)
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func TestResolveConfigPath_ExplicitMissing(t *testing.T) {
	path, ok := resolveConfigPath(filepath.Join(t.TempDir(), "nope.toml"))
	if ok || path != "" {
		t.Errorf("resolveConfigPath(missing) = (%q, %v), want (\"\", false)", path, ok)
	}
}

func TestResolveConfigPath_ExplicitExists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "spec.toml")
	if err := os.WriteFile(p, []byte("version=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	path, ok := resolveConfigPath(p)
	if !ok || path != p {
		t.Errorf("resolveConfigPath(existing) = (%q, %v), want (%q, true)", path, ok, p)
	}
}

func TestResolveConfigPath_DefaultLocation(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "uml"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uml", "agentpvm.toml"), []byte("version=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)
	path, ok := resolveConfigPath("")
	if !ok || path != defaultConfigPath {
		t.Errorf("resolveConfigPath(\"\") with ./uml/agentpvm.toml present = (%q, %v), want (%q, true)",
			path, ok, defaultConfigPath)
	}
}

func TestResolveConfigPath_FallsBackToDefaults(t *testing.T) {
	chdir(t, t.TempDir()) // empty dir: no ./uml/agentpvm.toml
	path, ok := resolveConfigPath("")
	if ok || path != "" {
		t.Errorf("resolveConfigPath(\"\") with no config anywhere = (%q, %v), want (\"\", false)", path, ok)
	}
}

func TestIDRegex(t *testing.T) {
	// sanitizeID turns an arbitrary ID string into a legal, recognizable
	// subtest name (letters, digits, underscore, dash, dot).
	sanitizeID := func(id string) string {
		var b strings.Builder
		for _, r := range id {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
				r == '-', r == '_', r == '.':
				b.WriteRune(r)
			default:
				b.WriteRune('_')
			}
		}
		if b.Len() == 0 {
			return "empty"
		}
		return b.String()
	}

	cases := []struct {
		id    string
		valid bool
	}{
		{"agent-task", true},
		{"tk_1", true},
		{"ABC123", true},
		{"a", true},
		{"x-y_z0", true},
		{"", false},
		{"../evil", false},
		{"a/b", false},
		{"a b", false},
		{"a;b", false},
		{"a$(id)", false},
		{"evil,opt=x", false},
		{"dot.name", false},
	}
	for _, tc := range cases {
		tc := tc
		verb := "rejects"
		if tc.valid {
			verb = "accepts"
		}
		t.Run(verb+"_"+sanitizeID(tc.id), func(t *testing.T) {
			if got := taskIDRe.MatchString(tc.id); got != tc.valid {
				t.Errorf("taskIDRe.MatchString(%q) = %v, want %v", tc.id, got, tc.valid)
			}
		})
	}
}

func TestSafeDefaultSpec(t *testing.T) {
	// Caller comes from $USER; pin it so the spec validates in CI containers
	// where USER may be unset.
	t.Setenv("USER", "tester")
	s := safeDefaultSpec()

	// The whole point of the fallback spec is default-deny: a misconfigured
	// launch must be SAFE, not useful.
	if s.Network.Enabled {
		t.Error("safe default must keep networking disabled (default-deny)")
	}
	if len(s.Tools) != 0 {
		t.Errorf("safe default must allow no tools, got %d rules", len(s.Tools))
	}
	if s.Runtime.Name == "" || s.Runtime.Memory == "" || s.Kernel.Path == "" {
		t.Errorf("safe default must still be launch-shaped, got %+v", s)
	}
	fp := s.Fingerprint()
	if len(fp) != 64 {
		t.Errorf("fingerprint = %q (len %d), want 64 hex chars", fp, len(fp))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Errorf("fingerprint = %q is not valid hexadecimal: %v", fp, err)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("safe default spec must validate cleanly: %v", err)
	}
	if s.Caller != "tester" {
		t.Errorf("caller = %q, want $USER (tester)", s.Caller)
	}
}

func TestRulesFromSpec(t *testing.T) {
	in := []spec.ToolRule{
		{Name: "shell", Action: "exec", Effect: "allow", Reason: "dev"},
		{Name: "send_email", Action: "*", Effect: "require_approval", Reason: "exfil risk"},
	}
	out := rulesFromSpec(in)
	if len(out) != len(in) {
		t.Fatalf("rulesFromSpec returned %d rules, want %d", len(out), len(in))
	}
	for i, r := range in {
		if out[i].Name != r.Name || out[i].Action != r.Action ||
			out[i].Effect != r.Effect || out[i].Reason != r.Reason {
			t.Errorf("rule %d mistranslated: got %+v, want %+v", i, out[i], r)
		}
	}
	// nil input must yield an empty (non-nil is fine either way) slice, not panic.
	if got := rulesFromSpec(nil); len(got) != 0 {
		t.Errorf("rulesFromSpec(nil) has %d rules, want 0", len(got))
	}
}
