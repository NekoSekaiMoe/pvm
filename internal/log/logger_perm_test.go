package log

import (
	"os"
	"path/filepath"
	"testing"

	"uml-container/internal/state"
)

// TestSetupConsoleLog_Permissions pins the hardening: the logs directory is
// 0700 and console.log 0600 — guest console output must not be readable by
// other local users. Also verifies a pre-existing file created with looser
// permissions gets tightened on reopen.
func TestSetupConsoleLog_Permissions(t *testing.T) {
	// Redirect the state root: the default (/var/lib/uml-container) is only
	// writable by root, and CI runs unprivileged.
	orig := state.RootDir
	state.RootDir = t.TempDir()
	defer func() { state.RootDir = orig }()

	f, err := SetupConsoleLog("c-perm")
	if err != nil {
		t.Fatalf("SetupConsoleLog: %v", err)
	}
	defer f.Close()

	dir, err := state.ContainerDir("c-perm")
	if err != nil {
		t.Fatalf("ContainerDir: %v", err)
	}
	dir = filepath.Join(dir, "logs")
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("logs dir mode = %v (err %v), want 0700", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "console.log")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("console.log mode = %v (err %v), want 0600", fi, err)
	}

	// Loosen both behind the API's back; a re-open must tighten them again.
	logPath := filepath.Join(dir, "console.log")
	if err := os.Chmod(logPath, 0o644); err != nil {
		t.Fatalf("chmod loosen: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod loosen dir: %v", err)
	}
	f2, err := SetupConsoleLog("c-perm")
	if err != nil {
		t.Fatalf("re-open SetupConsoleLog: %v", err)
	}
	defer f2.Close()
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("logs dir mode after re-open = %v (err %v), want 0700", fi, err)
	}
	if fi, err := os.Stat(logPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("console.log mode after re-open = %v (err %v), want 0600", fi, err)
	}
}
