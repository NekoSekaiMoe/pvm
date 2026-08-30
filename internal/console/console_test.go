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
	got, err := s.waitTailSince(context.Background(), off0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-after-wrap" {
		t.Fatalf("since-offset broken after wrap: %q", got)
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
