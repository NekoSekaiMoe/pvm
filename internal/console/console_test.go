package console

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExecMarkerProtocol(t *testing.T) {
	m := &Manager{sessions: map[string]*Session{}}
	sess := m.Attach("t-1")

	// Fake guest with a pty-like behavior: echo stdin lines to output and
	// respond to marker echoes.
	inR, inW, _ := os.Pipe()
	sess.SetStdin(inW)
	go func() {
		sc := bufio.NewScanner(inR)
		for sc.Scan() {
			line := sc.Text()
			// echo the typed line (interactive tty behavior)
			sess.Write([]byte(line + "\r\n"))
			if cmd, ok := strings.CutPrefix(line, "echo "); ok {
				cmd = strings.Trim(cmd, `"`)
				if strings.HasPrefix(cmd, "__PVM_B_") {
					sess.Write([]byte(cmd + "\n"))
				} else if strings.HasPrefix(cmd, "__PVM_E_") {
					sess.Write([]byte(strings.Replace(cmd, "$?", "7", 1) + "\n"))
				}
			}
		}
	}()

	res, err := sess.Exec(context.Background(), "true", 5*time.Second)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("expected exit 7 from fake guest, got %d", res.ExitCode)
	}
}

func TestExecNoStdin(t *testing.T) {
	m := &Manager{sessions: map[string]*Session{}}
	sess := m.Attach("t-2")
	if _, err := sess.Exec(context.Background(), "ls", time.Second); err != ErrNoStdin {
		t.Fatalf("expected ErrNoStdin, got %v", err)
	}
}

type execTestStdin func([]byte) (int, error)

func (w execTestStdin) Write(p []byte) (int, error) { return w(p) }
func (w execTestStdin) Close() error                { return nil }

func TestExecQueuedContextCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			sess := newSession("queued-"+name, defaultRingSize)
			writes := make(chan struct{}, 2)
			release := make(chan struct{})
			sess.SetStdin(execTestStdin(func(p []byte) (int, error) {
				writes <- struct{}{}
				<-release
				return 0, io.ErrClosedPipe
			}))
			activeDone := make(chan error, 1)
			go func() {
				_, err := sess.Exec(context.Background(), "active", time.Second)
				activeDone <- err
			}()
			t.Cleanup(func() {
				close(release)
				select {
				case err := <-activeDone:
					if !errors.Is(err, io.ErrClosedPipe) {
						t.Errorf("active exec: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Error("active exec did not finish after stdin was released")
				}
				// The stdin error must also release the execution slot.
				sess.SetStdin(nil)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if _, err := sess.Exec(ctx, "next", time.Second); err != ErrNoStdin {
					t.Errorf("exec after stdin error: %v", err)
				}
			})
			select {
			case <-writes:
			case <-time.After(2 * time.Second):
				t.Fatal("active exec did not reach stdin")
			}

			ctx, cancel := context.WithCancel(context.Background())
			wantErr := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
				wantErr = context.DeadlineExceeded
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := sess.Exec(ctx, "queued", time.Second)
				done <- err
			}()
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, wantErr) {
					t.Fatalf("queued exec: got %v, want %v", err, wantErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("queued exec did not return while active stdin was blocked")
			}
			select {
			case <-writes:
				t.Fatal("canceled queued exec wrote to stdin")
			default:
			}
		})
	}
}

func TestExecSerializesWithoutChargingQueueTime(t *testing.T) {
	sess := newSession("serialized", defaultRingSize)
	writes := make(chan string, 2)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	sess.SetStdin(execTestStdin(func(p []byte) (int, error) {
		lines := strings.Split(string(p), "\n")
		cmd := lines[2]
		writes <- cmd
		if cmd == "first" {
			<-release
		}
		begin := strings.Trim(strings.TrimPrefix(lines[1], "echo "), `"`)
		end := strings.Trim(strings.TrimPrefix(lines[3], "echo "), `"`)
		_, err := sess.Write([]byte(begin + "\n" + cmd + "\n" + strings.Replace(end, "$?", "0", 1) + "\n"))
		return len(p), err
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	run := func(cmd string, done chan<- error) {
		res, err := sess.Exec(ctx, cmd, 100*time.Millisecond)
		if err == nil && (res.Stdout != cmd+"\n" || res.ExitCode != 0) {
			err = errors.New("exec returned incorrect output or exit code")
		}
		done <- err
	}
	go run("first", firstDone)
	select {
	case <-writes:
	case <-ctx.Done():
		t.Fatal("first exec did not reach stdin")
	}
	go run("second", secondDone)
	// Keep the first exec blocked longer than the second exec's timeout.
	select {
	case cmd := <-writes:
		t.Fatalf("exec %q wrote before the first exec completed", cmd)
	case err := <-secondDone:
		t.Fatalf("queued exec returned before acquiring its slot: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	for _, done := range []<-chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("exec: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("exec did not finish after the first stdin write was released")
		}
	}
}

func TestRingWrapAndTail(t *testing.T) {
	s := newSession("t-3", 64)
	// Write 200 bytes; ring keeps last 64.
	chunk := strings.Repeat("x", 100)
	s.Write([]byte(chunk))
	s.Write([]byte(chunk))
	tail := s.Tail(16)
	if len(tail) != 16 {
		t.Fatalf("tail len = %d", len(tail))
	}
	// Since-offsets stay monotonic across wraps.
	off0 := int(s.total)
	s.Write([]byte("hello-after-wrap"))
	got, end, err := s.waitTailSince(context.Background(), off0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-after-wrap" {
		t.Fatalf("since-offset broken after wrap: %q", got)
	}
	if end != s.total {
		t.Fatalf("end offset = %d, want the true total %d", end, s.total)
	}
}

func TestManagerGetDetach(t *testing.T) {
	m := &Manager{sessions: map[string]*Session{}}
	_ = m.Attach("a")
	if _, err := m.Get("a"); err != nil {
		t.Fatalf("get: %v", err)
	}
	m.Detach("a")
	if _, err := m.Get("a"); err != ErrNoSession {
		t.Fatalf("expected ErrNoSession after detach, got %v", err)
	}
	m.Detach("a") // idempotent
}

func TestSessionSinceStreaming(t *testing.T) {
	m := defaultManager
	sess := m.Attach("sse-test")
	defer m.Detach("sse-test")

	if _, err := sess.Write([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	t.Run("initial data", func(t *testing.T) {
		chunk, off, err := sess.Since(ctx, 0, 500*time.Millisecond)
		if err != nil || string(chunk) != "hello " || off != 6 {
			t.Fatalf("Since = %q %d %v", chunk, off, err)
		}
	})

	var off int64
	t.Run("idle timeout keeps offset", func(t *testing.T) {
		_, o, err := sess.Since(ctx, 6, 50*time.Millisecond)
		if err == nil || o != 6 {
			t.Fatalf("idle Since must time out in place: %d %v", o, err)
		}
		off = o
	})

	t.Run("subsequent data", func(t *testing.T) {
		if _, err := sess.Write([]byte("world")); err != nil {
			t.Fatal(err)
		}
		chunk, o, err := sess.Since(ctx, off, 500*time.Millisecond)
		if err != nil || string(chunk) != "world" || o != 11 {
			t.Fatalf("Since#2 = %q %d %v", chunk, o, err)
		}
	})
}

// Regression: after the ring wraps, a stale (too-old) offset must clamp
// FORWARD, the returned end offset must be the true ring end, and the next
// Since must not resend bytes the caller already saw.
func TestSessionSinceRingWrapNoResend(t *testing.T) {
	s := newSession("wrap-test", 8)
	if _, err := s.Write([]byte("01234567890123456789")); err != nil { // total=20, ring holds last 8
		t.Fatal(err)
	}
	chunk, next, err := s.Since(context.Background(), 0, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk) != "23456789" {
		t.Fatalf("clamped chunk = %q, want the held window %q", chunk, "23456789")
	}
	if next != 20 {
		t.Fatalf("next = %d, want the true end 20 (not off+len(chunk))", next)
	}
	if _, err := s.Write([]byte("xyz")); err != nil {
		t.Fatal(err)
	}
	chunk2, _, err := s.Since(context.Background(), next, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk2) != "xyz" {
		t.Fatalf("after wrap, Since resent old data: %q", chunk2)
	}
}

// TestRingTwoSegmentReadCrossesWrap drives many small writes across the
// wrap point and verifies every absolute window reads back byte-exact —
// the two-segment copy path (tail segment + rewound head segment) is where
// a true ring implementation most easily corrupts data.
func TestRingTwoSegmentReadCrossesWrap(t *testing.T) {
	s := newSession("seg-test", 16)
	// Fill exactly to capacity so the NEXT write starts evicting.
	s.Write([]byte("ABCDEFGHIJKLMNOP"))
	for i := 0; i < 40; i++ {
		b := byte('a' + i%26)
		if _, err := s.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
		// Read the full held window and verify it is exactly the last 16
		// bytes of the stream so far.
		out, _, err := s.Since(context.Background(), 0, 200*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		total := int(s.Total())
		want := make([]byte, 0, 16)
		for j := total - len(out); j < total; j++ {
			if j < 16 {
				want = append(want, byte('A'+j))
			} else {
				want = append(want, byte('a'+(j-16)%26))
			}
		}
		if string(out) != string(want) {
			t.Fatalf("iter %d: window corrupted:\n got %q\nwant %q", i, out, want)
		}
	}
}
