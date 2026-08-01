package vhost

import (
	"sync"
	"testing"
	"time"
)

// TestVirtQueue_WaitIO_BlocksUntilInFlightDone verifies the SET_MEM_TABLE
// memory-lifetime contract (#3): WaitIO must not return while an IO goroutine
// is still running, and must return once every startIO is matched by endIO.
// Without this, UnmapAll could Munmap a region a completing read still writes
// into.
func TestVirtQueue_WaitIO_BlocksUntilInFlightDone(t *testing.T) {
	vq := &VirtQueue{Num: 1}
	vq.ioSem = make(chan struct{}, 4)

	// Register an in-flight IO FIRST, so WaitIO observes a non-zero count.
	vq.startIO()

	waitDone := make(chan struct{})
	go func() {
		vq.WaitIO()
		close(waitDone)
	}()

	// While the IO is in flight, WaitIO must still be blocked.
	if signaled(waitDone) {
		t.Fatal("WaitIO returned before in-flight IO finished")
	}

	// Complete the IO; WaitIO should now return.
	vq.endIO()
	if !signaledAfter(waitDone, time.Second) {
		t.Fatal("WaitIO did not return after all IO completed")
	}
}

// TestVirtQueue_IOSemaphoreBounded verifies the concurrency bound (#4): startIO
// must block once the semaphore is exhausted, and unblock as a slot frees.
func TestVirtQueue_IOSemaphoreBounded(t *testing.T) {
	vq := &VirtQueue{Num: 1}
	vq.ioSem = make(chan struct{}, 2)

	vq.startIO()
	vq.startIO()

	// A third startIO must block (semaphore exhausted).
	got := make(chan struct{})
	go func() {
		vq.startIO()
		close(got)
	}()
	if signaled(got) {
		t.Fatal("startIO returned despite semaphore exhaustion (no bound)")
	}
	// Free a slot; the pending startIO should now complete.
	vq.endIO()
	if !signaledAfter(got, time.Second) {
		t.Fatal("startIO still blocked after a slot was freed")
	}
	// Drain the two slots we still hold.
	vq.endIO()
	vq.endIO()
	vq.WaitIO()
}

// TestVirtQueue_StartIOWithoutSemaphore verifies early-path safety: a
// VirtQueue whose ioSem is nil (queue not fully configured) runs unbounded and
// WaitIO still tracks goroutines correctly.
func TestVirtQueue_StartIOWithoutSemaphore(t *testing.T) {
	vq := &VirtQueue{Num: 1} // ioSem == nil

	vq.startIO()
	waitDone := make(chan struct{})
	go func() {
		vq.WaitIO()
		close(waitDone)
	}()
	if signaled(waitDone) {
		t.Fatal("WaitIO returned with outstanding IO")
	}
	vq.endIO()
	if !signaledAfter(waitDone, time.Second) {
		t.Fatal("WaitIO did not return after IO completed")
	}
}

// signaled reports whether ch has been closed, without blocking.
func signaled(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// signaledAfter waits up to timeout for ch to close. It avoids flakiness from
// goroutine scheduling while still bounding the test.
func signaledAfter(ch <-chan struct{}, timeout time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

// silence unused import if a future trim removes the WaitGroup use.
var _ = sync.WaitGroup{}
