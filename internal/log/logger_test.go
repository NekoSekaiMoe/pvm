package log

import (
	"os"
	"path/filepath"
	"testing"
	"uml-container/internal/state"
)

func TestSetupConsoleLog_CreatesFile(t *testing.T) {
	root := t.TempDir()
	orig := state.RootDir
	state.RootDir = root
	defer func() { state.RootDir = orig }()

	f, err := SetupConsoleLog("c-log")
	if err != nil {
		t.Fatalf("SetupConsoleLog: %v", err)
	}
	defer f.Close()

	expected := filepath.Join(root, "c-log", "logs", "console.log")
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("console.log not created at expected path: %v", err)
	}

	if _, err := f.WriteString("hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()
	data, err := os.ReadFile(expected)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "hello\n" {
		t.Errorf("log contents = %q", data)
	}
}

func TestSetupConsoleLog_InvalidID(t *testing.T) {
	// Invalid IDs (path separators, etc.) must be rejected by state.ContainerDir
	// and surface here, never creating directories outside the root.
	_, err := SetupConsoleLog("../escape")
	if err == nil {
		t.Fatalf("expected error for invalid container ID, got nil")
	}
}
