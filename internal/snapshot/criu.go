package snapshot

// criu.go adds memory-state capture to snapshots (bucket-5 "内存快照").
//
// UML is a normal host process, so CRIU can checkpoint it wholesale: the
// dump lands next to the disk snapshot and restore revives the exact guest
// execution state (open FDs, memory, processes) — not just the filesystem.
//
// Degradation is explicit and auditable: without a CRIU binary (or on
// failure), CreateEventSnapshot records memory_state="degraded" and the
// snapshot still captures disk + FSM state. A restore from a degraded
// snapshot boots fresh from disk; callers must be able to tell the
// difference (EventSnapshot.MemoryState).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// MemoryState classifies what a snapshot captured.
type MemoryState string

const (
	MemoryFull       MemoryState = "full"     // CRIU dump succeeded
	MemoryDegraded   MemoryState = "degraded" // no CRIU / dump failed: disk-only
	MemoryNotAttempt MemoryState = "n/a"      // no running process to dump
)

// ErrCRIUUnavailable marks the graceful no-CRIU path.
var ErrCRIUUnavailable = fmt.Errorf("snapshot: criu binary not available")

// CRIUBin resolves the criu binary (PVM_CRIU_BIN override, then PATH).
func CRIUBin() string {
	if v := os.Getenv("PVM_CRIU_BIN"); v != "" {
		return v
	}
	if p, err := exec.LookPath("criu"); err == nil {
		return p
	}
	return ""
}

// DumpMemory checkpoints pid into dir (criu images). With leaveRunning the
// guest keeps executing (checkpoint-and-continue); otherwise it is stopped
// (checkpoint-and-stop, the pause path).
func DumpMemory(pid int, dir string, leaveRunning bool) error {
	bin := CRIUBin()
	if bin == "" {
		return ErrCRIUUnavailable
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	args := []string{"dump", "--tree", fmt.Sprint(pid), "--images-dir", dir, "--shell-job"}
	if leaveRunning {
		args = append(args, "--leave-running")
	}
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("snapshot: criu dump: %v: %s", err, lastN(string(out), 400))
	}
	return nil
}

// RestoreMemory revives a dumped process tree from dir.
func RestoreMemory(dir string) error {
	bin := CRIUBin()
	if bin == "" {
		return ErrCRIUUnavailable
	}
	cmd := exec.Command(bin, "restore", "--images-dir", dir, "--shell-job")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("snapshot: criu restore: %v: %s", err, lastN(string(out), 400))
	}
	return nil
}

// MemoryImagesDir is where DumpMemory writes inside a snapshot dir.
func MemoryImagesDir(snapDir string) string { return filepath.Join(snapDir, "criu") }

// copyMeta clones a caller's metadata map before the snapshot layer adds
// its own keys (memory_state et al.) — CreateEventSnapshot must never
// mutate a map it does not own.
func copyMeta(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
