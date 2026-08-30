// Package logx provides size-based log rotation for console log files
// (bucket-2 gap: console.log grew unbounded). Rotation keeps N suffix
// generations (.1 newest .. .N oldest) and reopens atomically; writes that
// race the rotate are serialized by the rotator's mutex.
package logx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Defaults; overridable via PVM_LOG_MAX_BYTES / PVM_LOG_KEEP.
const (
	DefaultMaxBytes = 8 << 20 // 8 MiB
	DefaultKeep     = 3
)

// Rotator is a size-rotating file writer (io.Writer + io.Closer).
type Rotator struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	written  int64
}

// NewRotator opens (creating if needed) path with rotation policy.
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
	return &Rotator{path: path, maxBytes: maxBytes, keep: keep, f: f, written: written}, nil
}

// Write appends p, rotating first when the current generation would exceed
// maxBytes. A single write larger than maxBytes still lands whole (rotation
// happens before, never mid-write).
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.written+int64(len(p)) > r.maxBytes {
		if err := r.rotateLocked(); err != nil {
			// Rotation failure must not lose the log line: fall through and
			// keep writing to the current file.
			_ = err
		}
	}
	n, err := r.f.Write(p)
	r.written += int64(n)
	return n, err
}

// Close closes the current generation.
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
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
