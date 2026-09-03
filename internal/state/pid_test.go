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
	spawn := func() *exec.Cmd {
		t.Helper()
		cmd := exec.Command(sleep, "30")
		if err := cmd.Start(); err != nil {
			t.Fatalf("spawn: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}

	t.Run("freshly stamped pid verifies", func(t *testing.T) {
		cmd := spawn()
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
	})

	t.Run("legacy live pid verifies by existence", func(t *testing.T) {
		cmd := spawn()
		st := &ContainerState{ID: "pidt", Status: StatusRunning, PID: cmd.Process.Pid}
		if !PIDIdentityOK(st) {
			t.Fatal("legacy live pid (no stamp) must verify by existence")
		}
	})

	t.Run("reaped pid must not verify", func(t *testing.T) {
		cmd := spawn()
		st := &ContainerState{ID: "pidt", Status: StatusRunning}
		StampPID(st, cmd.Process.Pid)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		deadline := time.Now().Add(5 * time.Second)
		for PIDIdentityOK(st) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if PIDIdentityOK(st) {
			t.Fatal("reaped pid must not verify")
		}
	})

	t.Run("nil state and pid zero never verify", func(t *testing.T) {
		if PIDIdentityOK(nil) || PIDIdentityOK(&ContainerState{}) {
			t.Fatal("nil state / pid 0 must not verify")
		}
	})

	t.Run("starttime mismatch is refused", func(t *testing.T) {
		// A recorded stamp that does not match the live process is
		// refused even though SOME process may hold the pid later.
		st2 := &ContainerState{ID: "pidt2", PID: 1, Metadata: map[string]string{MetaPIDStart: "424242"}}
		if PIDIdentityOK(st2) {
			t.Fatal("starttime mismatch must be refused")
		}
	})
}
