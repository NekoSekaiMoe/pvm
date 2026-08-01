package uml

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDefaultLauncher_WaitDrainsPipes verifies the review-fix for item 3:
// Wait must not return until the io.Copy goroutines have drained stdout/stderr,
// otherwise the console log gets truncated. We run a real `sh -c` that writes a
// sentinel then exits; if Wait raced the pipes, the sentinel could be lost.
func TestDefaultLauncher_WaitDrainsPipes(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}

	logDir := t.TempDir()
	logFile := filepath.Join(logDir, "console.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}

	const sentinel = "UML_DRAIN_MARKER_LINE"
	// Write many lines so there's real pipe pressure; a single small write
	// might slip through even with a broken Wait.
	script := "for i in $(seq 1 200); do echo " + sentinel + "; done"

	l := &DefaultLauncher{}
	pid, p, err := l.Start(context.Background(), sh, []string{"-c", script}, f)
	if err != nil {
		f.Close()
		t.Fatalf("Start: %v", err)
	}
	if pid <= 0 {
		t.Errorf("unexpected pid %d", pid)
	}

	// Wait must drain before returning; closing the log file afterwards is the
	// caller's responsibility (matching container/manager.go's pattern).
	if err := l.Wait(p); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	f.Close()

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	got := string(data)
	if strings.Count(got, sentinel) != 200 {
		t.Errorf("sentinel count = %d, want 200 (log truncated by Wait race?)\n---\n%s", strings.Count(got, sentinel), got)
	}
}

func TestDefaultLauncher_StartReportsExecErrors(t *testing.T) {
	l := &DefaultLauncher{}
	_, _, err := l.Start(context.Background(), "/no/such/kernel", nil, nil)
	if err == nil {
		t.Fatalf("expected error for missing kernel binary, got nil")
	}
}

// TestBuildCmd_StraceWrapped verifies that setting UML_STRACE launches the
// kernel under strace writing next to the console log, so a hang can be
// diagnosed from the syscall trace. It requires strace on PATH (CI has it);
// otherwise the test is skipped rather than failed.
func TestBuildCmd_StraceWrapped(t *testing.T) {
	if _, err := exec.LookPath("strace"); err != nil {
		t.Skip("strace not on PATH")
	}
	logDir := t.TempDir()
	logFile, err := os.OpenFile(filepath.Join(logDir, "console.log"), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer logFile.Close()

	t.Setenv("UML_STRACE", "1")
	l := &DefaultLauncher{}
	cmd := l.buildCmd(context.Background(), "/path/to/linux", []string{"init=/init.sh", "mem=512M"}, logFile)

	if len(cmd.Args) == 0 || filepath.Base(cmd.Args[0]) != "strace" {
		t.Fatalf("expected strace as argv[0], got %#q", cmd.Args)
	}
	// -o target must be the strace.log beside console.log.
	wantOut := filepath.Join(logDir, "strace.log")
	foundOut := false
	for i, a := range cmd.Args {
		if a == "-o" && i+1 < len(cmd.Args) && cmd.Args[i+1] == wantOut {
			foundOut = true
		}
	}
	if !foundOut {
		t.Errorf("strace args %#q missing -o %s", cmd.Args, wantOut)
	}
	// Must trace all forks (-f) so UML child threads are covered.
	if !sliceContains(cmd.Args, "-f") {
		t.Errorf("strace args %#q missing -f (follow forks)", cmd.Args)
	}
	// Kernel + its args come after --.
	sep := -1
	for i, a := range cmd.Args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(cmd.Args) || cmd.Args[sep+1] != "/path/to/linux" {
		t.Errorf("strace args %#q do not pass kernel after --", cmd.Args)
	}
}

// TestBuildCmd_NoStraceWithoutEnv verifies the default path: without UML_STRACE
// the kernel is launched directly (no tracer wrapper), so normal startup
// performance/behavior is unaffected.
func TestBuildCmd_NoStraceWithoutEnv(t *testing.T) {
	os.Unsetenv("UML_STRACE")
	l := &DefaultLauncher{}
	cmd := l.buildCmd(context.Background(), "/path/to/linux", []string{"mem=512M"}, nil)
	if cmd.Args[0] != "/path/to/linux" {
		t.Errorf("expected direct kernel launch, got %#q", cmd.Args)
	}
}

func sliceContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// TestProcess_WaitGroupSafeOnStartFailure ensures Start's WaitGroup won't
// deadlock Wait if cmd.Start itself fails after pipes were created.
func TestProcess_WaitGroupSafeOnStartFailure(t *testing.T) {
	// A non-existent kernel: StdoutPipe/StderrPipe succeed (cmd not started),
	// then cmd.Start fails. Start must not leave wg counting pending copies.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := (&DefaultLauncher{}).Start(ctx, "/no/such/kernel", nil, nil)
	if err == nil {
		t.Fatal("expected Start error")
	}
}
