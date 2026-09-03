// Package console provides guest-console sessions for UML containers: a
// per-container ring buffer of console output plus a stdin writer, and a
// line-marker exec protocol that runs commands in the guest's interactive
// console shell and captures stdout/stderr plus exit code.
//
// This is pvm's "guest agent": instead of baking a daemon into every rootfs,
// the host drives the console the operator would otherwise use by hand. It
// requires the guest to boot to an interactive shell on the console (the
// default for the minimal rootfses pvm ships). Sessions degrade gracefully:
// containers booted without a console session (interactive mode, or an old
// server process) report ErrNoSession and callers fall back.
package console

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrNoSession is returned when the container has no attached console
// session (interactive boot, already exited, or pre-upgrade process).
var ErrNoSession = errors.New("console: no session attached")

// ErrNoStdin is returned when the session exists but the guest console has
// no writable stdin channel.
var ErrNoStdin = errors.New("console: session has no stdin writer")

// Result carries one console exec outcome.
type Result struct {
	Stdout   string
	ExitCode int
	// Duration is wall time from marker write to END marker observation.
	Duration time.Duration
	// Simulated marks results produced by the sim backend (no guest).
	Simulated bool
}

// Session is one container's console. Output written by the guest is
// appended (by the launcher's copy goroutines through a TeeWriter) to the
// ring buffer; marker waits scan the tail; stdin writes reach the guest's
// console input.
type Session struct {
	id string

	mu     sync.Mutex
	cond   *sync.Cond
	ring   []byte
	maxLen int
	// total counts every byte ever appended; the ring holds the last
	// maxLen of them. Offsets handed to waitTailSince are absolute
	// (monotonic), so ring wrap-around cannot alias positions.
	total int64

	stdinMu sync.Mutex
	stdin   io.WriteCloser

	closed bool
}

const defaultRingSize = 256 * 1024

func newSession(id string, ringSize int) *Session {
	if ringSize <= 0 {
		ringSize = defaultRingSize
	}
	s := &Session{id: id, ring: make([]byte, 0, ringSize), maxLen: ringSize}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// ID returns the container id the session belongs to.
func (s *Session) ID() string { return s.id }

// Write appends guest output to the ring buffer (io.Writer contract so the
// launcher can tee into it via io.MultiWriter).
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.ring = append(s.ring, p...)
	if len(s.ring) > s.maxLen {
		s.ring = append(s.ring[:0], s.ring[len(s.ring)-s.maxLen:]...)
	}
	s.total += int64(len(p))
	s.cond.Broadcast()
	s.mu.Unlock()
	return len(p), nil
}

// SetStdin attaches the guest console stdin writer (the exec.Cmd pipe).
func (s *Session) SetStdin(w io.WriteCloser) {
	s.stdinMu.Lock()
	s.stdin = w
	s.stdinMu.Unlock()
}

// Stdin returns the current stdin writer (nil when absent).
func (s *Session) Stdin() io.WriteCloser {
	s.stdinMu.Lock()
	defer s.stdinMu.Unlock()
	return s.stdin
}

// Close marks the session dead and wakes all waiters.
func (s *Session) Close() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Tail returns up to max bytes of the most recent console output.
func (s *Session) Tail(max int) []byte {
	if max <= 0 {
		max = 4096
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ring) <= max {
		out := make([]byte, len(s.ring))
		copy(out, s.ring)
		return out
	}
	out := make([]byte, max)
	copy(out, s.ring[len(s.ring)-max:])
	return out
}

// Total returns the absolute append counter (monotonic; see Since).
func (s *Session) Total() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

// Since blocks until bytes beyond the absolute offset off appear (bounded
// by timeout) and returns them with the new absolute offset. The exported
// form of waitTailSince for streaming consumers (SSE console tail).
func (s *Session) Since(ctx context.Context, off int64, timeout time.Duration) ([]byte, int64, error) {
	chunk, end, err := s.waitTailSince(ctx, int(off), timeout)
	if err != nil {
		return nil, off, err
	}
	return chunk, end, nil
}

// waitTailSince blocks until bytes beyond the absolute offset off are
// available (or timeout/context fires) and returns them together with the
// ABSOLUTE end offset they were read to. off values are monotonic totals;
// when the ring has wrapped, the oldest still-held byte is at
// total-len(ring) and off below that is clamped to it — the returned end
// reflects the clamped start, so callers never derive a stale next offset.
func (s *Session) waitTailSince(ctx context.Context, off int, timeout time.Duration) ([]byte, int64, error) {
	deadline := time.Now().Add(timeout)
	done := ctx.Done()
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, 0, io.ErrClosedPipe
		}
		oldest := s.total - int64(len(s.ring))
		if int64(off) < oldest {
			off = int(oldest)
		}
		if s.total > int64(off) {
			start := int64(off) - oldest
			out := make([]byte, s.total-int64(off))
			copy(out, s.ring[start:])
			end := s.total
			s.mu.Unlock()
			return out, end, nil
		}
		s.mu.Unlock()

		// sync.Cond has no context integration; poll at a small interval
		// instead of blocking indefinitely on Broadcast.
		select {
		case <-time.After(50 * time.Millisecond):
			if time.Now().After(deadline) {
				return nil, 0, fmt.Errorf("console: tail wait timeout after %s", timeout)
			}
		case <-done:
			return nil, 0, ctx.Err()
		}
	}
}

// Manager tracks live console sessions keyed by container id. The package
// default is process-global so the API layer can reach sessions created by
// the container manager without plumbing.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

var defaultManager = &Manager{sessions: map[string]*Session{}}

// Default returns the process-global console manager.
func Default() *Manager { return defaultManager }

// Attach creates (or returns) the session for id.
func (m *Manager) Attach(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		return s
	}
	s := newSession(id, defaultRingSize)
	m.sessions[id] = s
	return s
}

// Get returns the session for id or ErrNoSession wrapped in nil.
func (m *Manager) Get(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok && !s.closed {
		return s, nil
	}
	return nil, ErrNoSession
}

// Detach closes and forgets the session for id (idempotent).
func (m *Manager) Detach(id string) {
	m.mu.Lock()
	s := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

// List returns the ids of all live sessions.
func (m *Manager) List() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	return ids
}

// markerEnd matches the END marker line: __PVM_E_<token>:<exit>__. The
// interactive shell echoes the typed command (literal $?), which must NOT
// match — the [0-9]+ requirement guarantees that.
func markerEnd(token string) *regexp.Regexp {
	return regexp.MustCompile(`__PVM_E_` + regexp.QuoteMeta(token) + `__:([0-9]+)`)
}

// Exec runs cmd in the guest's console shell and captures its output.
//
// Protocol: two marker echoes bracket the command. BEGIN is written before
// the command; END carries the command's exit status ($? expanded by the
// guest shell — the echoed literal `$?` in the input stream does not match
// the numeric pattern). Everything between the markers is the output.
func (s *Session) Exec(ctx context.Context, cmd string, timeout time.Duration) (*Result, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	w := s.Stdin()
	if w == nil {
		return nil, ErrNoStdin
	}

	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	begin := []byte("__PVM_B_" + token + "__")
	endRe := markerEnd(token)

	s.mu.Lock()
	startOff := int(s.total)
	s.mu.Unlock()

	started := time.Now()
	// Newlines before/after keep markers on their own lines even when the
	// console echo interleaves with a pending prompt.
	script := fmt.Sprintf("\necho %q\n%s\necho \"__PVM_E_%s__:$?\"\n", begin, cmd, token)
	if _, err := w.Write([]byte(script)); err != nil {
		return nil, fmt.Errorf("console: stdin write: %w", err)
	}

	var collected []byte
	off := int64(startOff)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		// Track the ABSOLUTE end offset: after a ring wrap the chunk may
		// start later than requested, and deriving the next offset from
		// the caller-side length would re-read already-returned bytes.
		chunk, next, err := s.waitTailSince(ctx, int(off), time.Until(deadline))
		if err != nil {
			break
		}
		off = next
		collected = append(collected, chunk...)
		if m := endRe.FindSubmatchIndex(collected); m != nil {
			exit := 0
			fmt.Sscanf(string(collected[m[2]:m[3]]), "%d", &exit)
			out := extractBetween(collected, begin, collected[m[0]:m[1]])
			return &Result{Stdout: out, ExitCode: exit, Duration: time.Since(started)}, nil
		}
	}
	return nil, fmt.Errorf("console: exec timed out after %s (no END marker; guest may not be at a shell prompt); collected tail: %q", timeout, tailN(collected, 300))
}

// tailN returns the last n bytes of buf.
func tailN(buf []byte, n int) []byte {
	if len(buf) <= n {
		return buf
	}
	return buf[len(buf)-n:]
}

// extractBetween trims everything up to the end of the BEGIN marker line and
// everything from the END marker line, returning the captured output.
func extractBetween(buf []byte, begin, end []byte) string {
	s := string(buf)
	bi := strings.Index(s, string(begin))
	if bi >= 0 {
		if nl := strings.IndexByte(s[bi:], '\n'); nl >= 0 {
			s = s[bi+nl+1:]
		} else {
			s = ""
		}
	}
	ei := strings.Index(s, string(end))
	if ei >= 0 {
		s = s[:ei]
	}
	// Drop the echoed command line when the console echoes input: the first
	// line after BEGIN is usually the echo of the command itself only when
	// it exactly matches; keep output verbatim otherwise.
	return strings.TrimLeft(s, "\r\n")
}

func randomToken() (string, error) {
	b := make([]byte, 6)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// PTY adapts a console session to the envd PTY surface: output streaming is
// the session's ring tail; input is stdin writes; resize is a no-op (the
// UML console is a fixed-width stream).
type PTY struct {
	session *Session
	id      string
	mu      sync.Mutex
	closed  bool
}

// OpenPTY registers a PTY handle on the session.
func (s *Session) OpenPTY(id string) *PTY { return &PTY{session: s, id: id} }

// Send writes user input to the guest console.
func (p *PTY) Send(input []byte) error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return io.ErrClosedPipe
	}
	w := p.session.Stdin()
	if w == nil {
		return ErrNoStdin
	}
	_, err := w.Write(input)
	return err
}

// Resize is a no-op for the fixed console (kept for envd API parity).
func (p *PTY) Resize(rows, cols int) error { return nil }

// Kill closes the PTY handle: subsequent Send/Tail calls fail with
// io.ErrClosedPipe (the console session itself stays attached for other
// handles).
func (p *PTY) Kill() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

// Tail streams new console output by polling the ring buffer.
func (p *PTY) Tail(ctx context.Context, since int, maxWait time.Duration) ([]byte, int, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, since, io.ErrClosedPipe
	}
	chunk, end, err := p.session.waitTailSince(ctx, since, maxWait)
	if err != nil {
		return nil, since, err
	}
	return chunk, int(end), nil
}

// CloseableStdin exposes the raw writer for launcher integration.
func (s *Session) writerForLauncher() io.Writer { return s }

var _ io.Writer = (*Session)(nil)

// randRead is indirected for tests.
var randRead = func(b []byte) (int, error) { return crand.Read(b) }

// TeeFor returns an io.Writer that fans console output into the session
// (used by the launcher via io.MultiWriter).
func (s *Session) TeeFor(logFile *os.File) io.Writer {
	if logFile == nil {
		return s
	}
	return io.MultiWriter(logFile, s)
}
