// Package logx provides size-based log rotation for console log files
// (bucket-2 gap: console.log grew unbounded). Rotation keeps N suffix
// generations (.1 newest .. .N oldest) and reopens atomically; writes that
// race the rotate are serialized by the rotator's mutex.
//
// Writes are BUFFERED (64 KiB) with a 500 ms flush ticker and a
// flush-on-rotate/Close: the console tee fans every guest output chunk
// into console.log + console.out.log, and the unbuffered form issued two
// raw pwrite syscalls per chunk (tens of bytes each) on the hot path.
// Durability of console logs is best-effort (they are diagnostics, not
// the audit ledger), so no fsync is added.
package logx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Defaults; overridable via PVM_LOG_MAX_BYTES / PVM_LOG_KEEP.
const (
	DefaultMaxBytes = 8 << 20 // 8 MiB
	DefaultKeep     = 3
	// bufSize is the write coalescing buffer; flushInterval bounds how
	// long a partial buffer may wait before landing on disk.
	bufSize       = 64 << 10
	flushInterval = 500 * time.Millisecond
)

// Rotator is a size-rotating file writer (io.Writer + io.Closer).
type Rotator struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	written  int64
	// buf coalesces writes; flusher is the ticker goroutine draining it.
	buf     []byte
	flusher *time.Ticker
	stopped chan struct{}
}

// NewRotator opens path for appending, creating its parent directories as
// needed. maxBytes is the generation size limit in bytes; keep is the number
// of rotated generations to retain. Nonpositive values use DefaultMaxBytes
// and DefaultKeep. Directory or file open failures are returned. Close must
// be called to flush buffered output and stop the background flusher.
func NewRotator(path string, maxBytes int64, keep int) (*Rotator, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if keep <= 0 {
		keep = DefaultKeep
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("logx: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("logx: open %s: %w", path, err)
	}
	fi, err := f.Stat()
	var written int64
	if err == nil {
		written = fi.Size()
	}
	r := &Rotator{
		path: path, maxBytes: maxBytes, keep: keep, f: f, written: written,
		buf: make([]byte, 0, bufSize), stopped: make(chan struct{}),
	}
	r.flusher = time.NewTicker(flushInterval)
	go r.flushLoop()
	return r, nil
}

// Write appends p, rotating first when the current generation would exceed
// maxBytes. A single write larger than maxBytes still lands whole (rotation
// happens before, never mid-write). p is coalesced into the write buffer
// and lands on disk when the buffer fills, the flush ticker fires, a
// rotation happens, or Close is called. The rotation check uses
// buffered+incoming bytes so the generation boundary granularity matches
// the unbuffered behavior. Success may mean p is only buffered; no fsync is
// performed. Write returns os.ErrClosed after closure, and propagates errors
// from foreground flushes, writes, and reopening after rotation. Background
// flush errors do not reach this caller.
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	// Oversized write: bypass the buffer entirely (no point copying it).
	if len(p) >= bufSize {
		if err := r.writeLocked(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	// Would adding p exceed the generation cap? Flush what's buffered and
	// rotate first — this keeps per-write rotation semantics identical to
	// the unbuffered implementation.
	if r.written+int64(len(r.buf))+int64(len(p)) > r.maxBytes {
		if err := r.writeLocked(nil); err != nil {
			return 0, err
		}
		if r.written+int64(len(p)) > r.maxBytes {
			if err := r.rotateLocked(); err != nil && r.f == nil {
				return 0, err
			}
		}
	}
	if len(r.buf)+len(p) > bufSize {
		if err := r.writeLocked(nil); err != nil {
			return 0, err
		}
	}
	r.buf = append(r.buf, p...)
	return len(p), nil
}

// writeLocked flushes the buffered bytes (if any) and writes p, rotating
// when the generation cap would be exceeded. Callers hold mu.
func (r *Rotator) writeLocked(p []byte) error {
	if len(r.buf) > 0 {
		if _, err := r.f.Write(r.buf); err != nil {
			return err
		}
		r.written += int64(len(r.buf))
		r.buf = r.buf[:0]
	}
	if len(p) == 0 {
		return nil
	}
	if r.written+int64(len(p)) > r.maxBytes {
		if err := r.rotateLocked(); err != nil && r.f == nil {
			// Rotation failed AFTER the old handle was closed (r.f == nil):
			// report the error instead of panicking on the nil handle. The
			// caller can retry once the underlying issue (permissions, disk)
			// is fixed; this line is lost, the process is not.
			return err
		}
	}
	n, err := r.f.Write(p)
	r.written += int64(n)
	return err
}

// flushLoop drains the write buffer on the ticker until stopped.
func (r *Rotator) flushLoop() {
	for {
		select {
		case <-r.stopped:
			return
		case <-r.flusher.C:
			r.mu.Lock()
			if r.f != nil && len(r.buf) > 0 {
				_ = r.writeLocked(nil)
			}
			r.mu.Unlock()
		}
	}
}

// Close flushes any buffered bytes, stops the flusher, and closes the
// current generation. Repeated calls after closure return nil. A buffer flush
// error takes precedence over a file close error.
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	r.flusher.Stop()
	close(r.stopped)
	var firstErr error
	if len(r.buf) > 0 {
		if err := r.writeLocked(nil); err != nil {
			firstErr = err
		}
	}
	err := r.f.Close()
	r.f = nil
	if firstErr != nil {
		return firstErr
	}
	return err
}

// rotateLocked shifts generations: path.(N-1)→path.N ... path→path.1, then
// reopens path fresh. Caller holds r.mu.
func (r *Rotator) rotateLocked() error {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	for i := r.keep - 1; i >= 1; i-- {
		older := fmt.Sprintf("%s.%d", r.path, i+1)
		newer := fmt.Sprintf("%s.%d", r.path, i)
		_ = os.Rename(newer, older)
	}
	_ = os.Rename(r.path, r.path+".1")
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("logx: reopen %s: %w", r.path, err)
	}
	r.f = f
	r.written = 0
	return nil
}

// Path returns the base path (testing/introspection).
func (r *Rotator) Path() string { return r.path }

var _ io.WriteCloser = (*Rotator)(nil)
