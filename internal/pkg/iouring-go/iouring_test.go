package iouring

import (
	"fmt"
	"os"
	"testing"
)

func testSubmitRequests(t *testing.T, nreqs uint) {
	f, err := os.Open("/dev/zero") // For read access.
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	iour, err := New(nreqs)
	if err != nil {
		t.Fatal(err)
	}
	defer iour.Close()

	fd := int(f.Fd())
	for iter := 0; iter < 2; iter++ {
		var offset uint64
		preqs := make([]PrepRequest, nreqs)
		bufs := make([][]byte, nreqs)
		for i := range preqs {
			bufs[i] = make([]byte, 2)
			preqs[i] = Pread(fd, bufs[i], offset)
			offset += 2
		}

		requests, err := iour.SubmitRequests(preqs, nil)
		if err != nil {
			t.Fatal(err)
		}
		<-requests.Done()
		errResults := requests.ErrResults()
		if errResults != nil {
			t.Fatal(errResults[0].Err())
		}
	}
}

func TestSubmitRequests(t *testing.T) {
	for i := uint(0); i < 8; i++ {
		nreqs := uint(1 << i)
		t.Run(fmt.Sprintf("%d", nreqs), func(t *testing.T) { testSubmitRequests(t, nreqs) })
	}
}

func TestTimeoutAndBuffers(t *testing.T) {
	iour, err := New(8)
	if err != nil {
		t.Fatal(err)
	}
	defer iour.Close()

	// Test Fixed Buffers Registration
	bufs := [][]byte{make([]byte, 1024), make([]byte, 1024)}
	if err := iour.RegisterBuffers(bufs); err != nil {
		t.Fatalf("RegisterBuffers failed: %v", err)
	}
	if err := iour.UnRegisterBuffers(); err != nil {
		t.Fatalf("UnRegisterBuffers failed: %v", err)
	}
	// Test empty buffers error
	if err := iour.RegisterBuffers(nil); err == nil {
		t.Fatal("RegisterBuffers with empty slice should fail")
	}

	// Test Timeout Success
	importTime := func() PrepRequest { return Timeout(0) }
	_ = importTime

	// We can use Timeout
	importTime2 := Timeout(1)
	req, err := iour.SubmitRequest(importTime2, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-req.Done()
	if err := req.Err(); err != nil && err.Error() != "timeout" && err.Error() != "timer expired" {
		t.Fatalf("Timeout returned unexpected error: %v", err)
	}

	// Test Timeout Cancel
	req2, err := iour.SubmitRequest(Timeout(1000000), nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Cancel()
	<-req2.Done()
	if err := req2.Err(); err != ErrRequestCanceled && err.Error() != "request is canceled" && err.Error() != "request canceled" {
		t.Fatalf("Timeout Cancel returned unexpected error: %v", err)
	}

	// Test RemoveTimeout
	req3, err := iour.SubmitRequest(Timeout(1000000), nil)
	if err != nil {
		t.Fatal(err)
	}
	req4, err := iour.SubmitRequest(RemoveTimeout(req3.ID()), nil)
	if err != nil {
		t.Fatal(err)
	}
	<-req4.Done()
	<-req3.Done()
	if err := req4.Err(); err != nil {
		t.Fatalf("RemoveTimeout returned unexpected error: %v", err)
	}
}
