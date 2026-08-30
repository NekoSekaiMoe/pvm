package snapshot

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// procStateField returns field 3 (state) of /proc/<pid>/stat, e.g. "T" for a
// stopped process, "R"/"S" for running/sleeping. Parsing mirrors procStartTime.
func procStateField(t *testing.T, pid int) string {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatalf("read /proc/%d/stat: %v", pid, err)
	}
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 || i+2 >= len(raw) {
		t.Fatalf("parse /proc/%d/stat: no fields after comm", pid)
	}
	fields := strings.Fields(string(raw[i+2:]))
	if len(fields) < 1 {
		t.Fatalf("parse /proc/%d/stat: empty fields", pid)
	}
	return fields[0]
}

// waitForProcState polls /proc until the child reaches one of the wanted
// states — signal delivery is asynchronous, so a single read may race.
func waitForProcState(t *testing.T, pid int, want map[string]bool, desc string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := procStateField(t, pid)
		if want[s] {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d never reached %s (last state %q)", pid, desc, s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startSleepChild launches `sleep 5` and registers cleanup; it also sanity
// checks pidMatchesStart against the child's actual /proc start time.
func startSleepChild(t *testing.T) (pid int, started time.Time) {
	t.Helper()
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	pid = cmd.Process.Pid
	started = procStartTime(pid)
	if started.IsZero() {
		t.Skipf("cannot read start time of pid %d from /proc", pid)
	}
	if !pidMatchesStart(pid, started) {
		t.Fatalf("pidMatchesStart: fresh child pid %d reported as PID reuse", pid)
	}
	if pidMatchesStart(pid, started.Add(-time.Hour)) {
		t.Fatalf("pidMatchesStart: child born an hour after `want` must be rejected (PID-reuse shape)")
	}
	return pid, started
}

// TestFreezeHandlePidfdStopCont: on kernels with pidfd_open, a freezeHandle
// must pin the child via pidfd; SIGSTOP moves it to state T and SIGCONT
// resumes it to R/S.
func TestFreezeHandlePidfdStopCont(t *testing.T) {
	if _, err := unix.PidfdOpen(os.Getpid(), 0); err != nil {
		t.Skipf("pidfd_open unavailable on this kernel: %v", err)
	}
	pid, _ := startSleepChild(t)

	h := newFreezeHandle(pid)
	if h.pidfd < 0 {
		t.Fatalf("newFreezeHandle: expected the pidfd path, got fallback")
	}
	defer h.close()

	if err := h.stop(); err != nil {
		t.Fatalf("stop via pidfd: %v", err)
	}
	waitForProcState(t, pid, map[string]bool{"T": true, "t": true}, "stopped (T)")

	h.cont()
	waitForProcState(t, pid, map[string]bool{"R": true, "S": true}, "resumed (R/S)")

	// close() must be idempotent (the deferred safety net may double-run).
	h.close()
}

// TestFreezeHandleFallbackStopCont: when pidfd_open fails (e.g. ENOSYS on
// pre-5.3 kernels), the handle degrades to kill-by-bare-PID and the
// freeze/thaw semantics stay identical.
func TestFreezeHandleFallbackStopCont(t *testing.T) {
	pid, _ := startSleepChild(t)

	orig := pidfdOpen
	pidfdOpen = func(pid int, flags int) (int, error) {
		return -1, unix.ENOSYS // simulate an old kernel
	}
	t.Cleanup(func() { pidfdOpen = orig })

	h := newFreezeHandle(pid)
	if h.pidfd >= 0 {
		t.Fatalf("newFreezeHandle: expected fallback (pidfd -1) after injected pidfd_open failure")
	}
	defer h.close()

	if err := h.stop(); err != nil {
		t.Fatalf("stop via kill fallback: %v", err)
	}
	waitForProcState(t, pid, map[string]bool{"T": true, "t": true}, "stopped (T)")

	h.cont()
	waitForProcState(t, pid, map[string]bool{"R": true, "S": true}, "resumed (R/S)")
}

// TestFreezeHandleContIgnoresDeadProcess: cont() after the pinned process
// exited must not panic or fail the flow (best-effort thaw, as documented).
func TestFreezeHandleContIgnoresDeadProcess(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait child: %v", err)
	}
	h := newFreezeHandle(cmd.Process.Pid)
	defer h.close()
	// Process (already reaped or a zombie): cont is best-effort by design.
	h.cont()
	var nilHandle *freezeHandle
	nilHandle.cont() // nil-safe for the non-dump path
	nilHandle.close()
}
