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
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

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

	mu   sync.Mutex
	cond *sync.Cond
	// ring is a TRUE circular buffer of maxLen bytes: head is the offset of
	// the oldest retained byte, size how many bytes are retained. The old
	// slice-shift design memmoved the whole 256KiB window on every
	// overflowing write (measured ~5.5µs/op steady state, ~100x a two-segment
	// ring copy), all under mu.
	ring   []byte
	head   int
	size   int
	maxLen int
	// total counts every byte ever appended; the ring holds the last
	// maxLen of them. Offsets handed to waitTailSince are absolute
	// (monotonic), so ring wrap-around cannot alias positions.
	total int64

	stdinMu sync.Mutex
	stdin   io.WriteCloser

	// execMu serializes Exec calls on one session: concurrent Execs would
	// interleave two marker scripts in the same stdin stream and attribute
	// output/exit codes to the wrong caller (the BEGIN/END markers of one
	// run could bracket the other's output).
	execMu sync.Mutex

	closed bool
}

const defaultRingSize = 256 * 1024

// newSession creates a session retaining ringSize bytes of console output.
// A nonpositive ringSize uses defaultRingSize; stdin must be attached separately.
func newSession(id string, ringSize int) *Session {
	if ringSize <= 0 {
		ringSize = defaultRingSize
	}
	s := &Session{id: id, ring: make([]byte, ringSize), maxLen: ringSize}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// ID returns the container id the session belongs to.
func (s *Session) ID() string { return s.id }

// Write appends guest output, retaining only the most recent maxLen bytes.
// It returns io.ErrClosedPipe if the session is closed. When p exceeds the
// window, only its tail is retained and the returned count is maxLen;
// otherwise the count is len(p).
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	n := len(p)
	s.total += int64(n)
	if n >= s.maxLen {
		// Keep the last maxLen bytes of p alone.
		p = p[n-s.maxLen:]
		n2 := copy(s.ring, p)
		s.head, s.size = 0, n2
	} else {
		// Advance head past the bytes this write evicts.
		drop := s.size + n - s.maxLen
		if drop > 0 {
			s.head = (s.head + drop) % s.maxLen
			s.size -= drop
		}
		tail := (s.head + s.size) % s.maxLen
		first := copy(s.ring[tail:], p)
		if first < len(p) {
			copy(s.ring, p[first:])
		}
		s.size += len(p)
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	return len(p), nil
}

// readAtLocked copies len(out) bytes starting at absolute offset off into out
// and returns the number copied. The requested range must be entirely within
// the retained output, and callers must hold mu.
func (s *Session) readAtLocked(off int64, out []byte) int {
	oldest := s.total - int64(s.size)
	start := int(off-oldest) + s.head
	n := copy(out, s.ring[start%s.maxLen:])
	if n < len(out) {
		n += copy(out[n:], s.ring[:])
	}
	return n
}

// oldestLocked is the absolute offset of the oldest retained byte.
func (s *Session) oldestLocked() int64 { return s.total - int64(s.size) }

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

// Tail returns a copy of up to max bytes of the most recent console output.
// A nonpositive max defaults to 4096 bytes.
func (s *Session) Tail(max int) []byte {
	if max <= 0 {
		max = 4096
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.size <= max {
		out := make([]byte, s.size)
		s.readAtLocked(s.oldestLocked(), out)
		return out
	}
	out := make([]byte, max)
	s.readAtLocked(s.total-int64(max), out)
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

// waitTailSince waits for bytes beyond the absolute append offset off and
// returns the retained bytes and their absolute end offset. An offset older
// than the retained window is clamped forward, so evicted bytes are omitted.
// A closed session returns io.ErrClosedPipe; cancellation returns ctx.Err(),
// and expiry without new output returns a timeout error.
func (s *Session) waitTailSince(ctx context.Context, off int, timeout time.Duration) ([]byte, int64, error) {
	deadline := time.Now().Add(timeout)
	done := ctx.Done()
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, 0, io.ErrClosedPipe
		}
		if oldest := s.oldestLocked(); int64(off) < oldest {
			off = int(oldest)
		}
		if s.total > int64(off) {
			out := make([]byte, s.total-int64(off))
			s.readAtLocked(int64(off), out)
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

// findMarkerEnd locates the END marker "__PVM_E_<token>__:<exit>" in
// collected bytes WITHOUT regex: the token is random so MustCompile ran per
// Exec (~20-50µs on the per-tool-call path). Returns (start, end, exit)
// with exit = -1 when no marker is present; end points just past the
// digits (mirroring the old regex `__PVM_E_<tok>__:([0-9]+)` capture
// semantics — no trailing bytes are required after the digits). The
// interactive shell echoes the typed command (literal $?), which must NOT
// match — the digit requirement guarantees that.
func findMarkerEnd(collected []byte, token string) (int, int, int) {
	prefix := []byte("__PVM_E_" + token + "__:")
	for from := 0; ; {
		i := bytes.Index(collected[from:], prefix)
		if i < 0 {
			return -1, -1, -1
		}
		start := from + i
		digits := start + len(prefix)
		j := digits
		for j < len(collected) && collected[j] >= '0' && collected[j] <= '9' {
			j++
		}
		if j > digits {
			exit := 0
			for _, c := range collected[digits:j] {
				exit = exit*10 + int(c-'0')
			}
			return start, j, exit
		}
		from = start + 1
	}
}

// Exec runs cmd in the guest's console shell and captures its output.
//
// Protocol: two marker echoes bracket the command. BEGIN is written before
// the command; END carries the command's exit status ($? expanded by the
// guest shell — the echoed literal `$?` in the input stream does not match
// the numeric pattern). Everything between the markers is the output.
// Output and exit status are guest-attested: a guest can forge the markers.
// A nonzero guest exit code is returned in Result, not as an error.
//
// Calls on one session are serialized. Nonpositive timeout defaults to 30
// seconds and bounds the marker wait after stdin is written, excluding time
// waiting for another Exec or writing stdin. Cancellation or timeout does
// not stop the guest command. Missing stdin returns ErrNoStdin; token and
// stdin write failures propagate. Cancellation checked before a tail wait
// returns ctx.Err(); tail-wait errors, including closure or cancellation,
// are converted to an exec timeout error.
func (s *Session) Exec(ctx context.Context, cmd string, timeout time.Duration) (*Result, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	// One marker protocol at a time per session: concurrent scripts would
	// interleave in the shared stdin/stdout stream and cross-attribute
	// output and exit codes between callers.
	s.execMu.Lock()
	defer s.execMu.Unlock()
	w := s.Stdin()
	if w == nil {
		return nil, ErrNoStdin
	}

	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	begin := []byte("__PVM_B_" + token + "__")

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
		// No fixed pre-sleep: waitTailSince blocks (bounded, ctx-aware)
		// until new bytes land or the deadline passes. The old shape slept
		// 100ms before the FIRST read, adding a flat 100-150ms to every
		// exec round-trip.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
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
		if ms, me, exit := findMarkerEnd(collected, token); ms >= 0 {
			out := extractBetween(collected, begin, collected[ms:me])
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
