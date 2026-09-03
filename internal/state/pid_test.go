package state

// pid_test.go — PID identity bookkeeping: stamp/read/verify round trip
// against real /proc data (a spawned child), including the recycled-pid
// refusal and the legacy no-stamp degradation.

import (
	"os/exec"
	"testing"
	"time"
)

func TestStampAndVerifyPIDIdentity(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	cmd := exec.Command(sleep, "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	st := &ContainerState{ID: "pidt", Status: StatusRunning}
	StampPID(st, cmd.Process.Pid)
	if st.PID != cmd.Process.Pid {
		t.Fatalf("PID = %d, want %d", st.PID, cmd.Process.Pid)
	}
	if st.Metadata[MetaPIDStart] == "" {
		t.Fatal("starttime stamp missing")
	}
	if !PIDIdentityOK(st) {
		t.Fatal("freshly stamped pid must verify")
	}

	// Legacy state (no stamp): existence-only verdict.
	delete(st.Metadata, MetaPIDStart)
	if !PIDIdentityOK(st) {
		t.Fatal("legacy live pid must verify by existence")
	}

	// Kill, wait for reaping, then the pid must not verify — and a
	// mismatched stamp must be refused even while the pid still exists.
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for PIDIdentityOK(st) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if PIDIdentityOK(st) {
		t.Fatal("reaped pid must not verify")
	}
	if PIDIdentityOK(nil) || PIDIdentityOK(&ContainerState{}) {
		t.Fatal("nil state / pid 0 must not verify")
	}
	// A recorded stamp that does not match the live process is refused
	// even though SOME process may hold the pid later.
	st2 := &ContainerState{ID: "pidt2", PID: 1, Metadata: map[string]string{MetaPIDStart: "424242"}}
	if PIDIdentityOK(st2) {
		t.Fatal("starttime mismatch must be refused")
	}
}
