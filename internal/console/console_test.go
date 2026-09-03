package console

import (
	"bufio"
	"context"
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
