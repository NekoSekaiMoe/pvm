// Package uidalloc maintains the centralized allocation table that assigns
// each container a dedicated 65536-wide host-uid range for its user
// namespace (the rootless jail: see TODO.md "[P1] Jail rootless 化").
//
// The manager runs as real root, so it can write arbitrary
// /proc/<pid>/uid_map entries — /etc/subuid and newuidmap are NOT involved.
// Each container gets its own disjoint range so that uid 0 inside container
// A's namespace maps to a different host uid than uid 0 inside container
// B's: containers share no kernel-side identity, and idmapped volume mounts
// can translate ownership per container.
//
// The table is persisted as JSON under the state root ($PVM_STATE_ROOT or
// /var/lib/uml-container/containers) so allocations survive manager
// restarts. Concurrency safety comes from two layers: an in-process mutex
// plus an flock(2) on the table file for cross-process safety (multiple
// umlctl/agentpvm processes may allocate concurrently).
//
// Leak policy: Allocate is idempotent per container ID, so a manager that
// crashed between Allocate and Release simply re-uses its old slot on the
// next launch of the same container. Release is called from container
// cleanup. Slots of long-gone containers can be reclaimed with Prune.
package uidalloc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// RangeSize is the uid/gid count mapped per container: the full
	// 0–65535 range so guest-side ownership (root + service users) survives
	// the mapping.
	RangeSize = 65536
	// FirstBase is the lowest host uid ever handed out. It sits above the
	// 0–65535 band used by host system users and matches the conventional
	// subuid start.
	FirstBase = 100000
)

// maxBase is the highest allocation base whose range still fits the 32-bit
// uid space: base + RangeSize - 1 <= math.MaxUint32.
const maxBase = 1<<32 - RangeSize

var idRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// diskState is the on-disk JSON schema of the allocation table.
type diskState struct {
	// Allocations maps container ID -> host uid range base.
	Allocations map[string]uint32 `json:"allocations"`
}

// Table is a handle to the persistent allocation table.
type Table struct {
	path string
	mu   sync.Mutex // in-process serialization; flock covers cross-process
}

// DefaultPath returns the table location under the state root, honoring
// $PVM_STATE_ROOT like internal/state does.
func DefaultPath() string {
	root := os.Getenv("PVM_STATE_ROOT")
	if root == "" {
		root = "/var/lib/uml-container/containers"
	}
	return filepath.Join(root, "uidmap.json")
}

// Open returns a table handle for the given path. The file is created lazily
// on the first mutating operation.
func Open(path string) (*Table, error) {
	if path == "" {
		return nil, fmt.Errorf("uidalloc: empty table path")
	}
	return &Table{path: path}, nil
}

// Allocate returns the host uid base for id, assigning the lowest free slot
// if the container has none yet. Idempotent: repeated calls with the same id
// return the same base, which lets a restarted manager recover its slot.
func (t *Table) Allocate(id string) (uint32, error) {
	if !idRe.MatchString(id) {
		return 0, fmt.Errorf("uidalloc: invalid container ID %q", id)
	}
	var base uint32
	err := t.mutate(func(st *diskState) error {
		if b, ok := st.Allocations[id]; ok {
			base = b
			return nil
		}
		b, err := lowestFree(st.Allocations)
		if err != nil {
			return err
		}
		st.Allocations[id] = b
		base = b
		return nil
	})
	return base, err
}

// Lookup returns the allocated base for id without assigning one.
func (t *Table) Lookup(id string) (uint32, bool, error) {
	if !idRe.MatchString(id) {
		return 0, false, fmt.Errorf("uidalloc: invalid container ID %q", id)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st, err := t.readLocked()
	if err != nil {
		return 0, false, err
	}
	b, ok := st.Allocations[id]
	return b, ok, nil
}

// Release frees id's slot. Releasing an unknown id is a no-op so cleanup
// paths can call it unconditionally.
func (t *Table) Release(id string) error {
	return t.mutate(func(st *diskState) error {
		delete(st.Allocations, id)
		return nil
	})
}

// Prune drops every allocation whose container ID is not in keep. The
// manager passes the set of containers that still exist (per internal/state)
// to reclaim slots leaked by crashes.
func (t *Table) Prune(keep map[string]bool) (int, error) {
	var n int
	err := t.mutate(func(st *diskState) error {
		for id := range st.Allocations {
			if !keep[id] {
				delete(st.Allocations, id)
				n++
			}
		}
		return nil
	})
	return n, err
}

// lowestFree finds the smallest base in [FirstBase, maxBase] that does not
// collide with any existing allocation's [base, base+RangeSize) interval.
// Bases are RangeSize-aligned offsets from FirstBase, so two distinct bases
// never partially overlap; an equality check on the aligned grid suffices.
func lowestFree(alloc map[string]uint32) (uint32, error) {
	used := make(map[uint32]bool, len(alloc))
	for _, b := range alloc {
		used[b] = true
	}
	for b := uint64(FirstBase); b <= maxBase; b += RangeSize {
		if !used[uint32(b)] {
			return uint32(b), nil
		}
	}
	return 0, fmt.Errorf("uidalloc: uid space exhausted (%d slots of %d uids)", len(alloc), RangeSize)
}

// mutate applies fn to the table state under the in-process mutex and an
// exclusive flock, persisting the result atomically enough for a
// crash-tolerant allocation table (write-then-fsync; a torn write is
// detected as JSON corruption and reported, never silently dropped).
func (t *Table) mutate(fn func(*diskState) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(t.path), 0700); err != nil {
		return fmt.Errorf("uidalloc: create state dir: %w", err)
	}
	f, err := os.OpenFile(t.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("uidalloc: open table: %w", err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("uidalloc: lock table: %w", err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)

	st, err := decode(f)
	if err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	// Always rewrite (even for no-op Release/Prune): the table is tiny and
	// the policy keeps the mutation path trivially correct.
	return write(f, st)
}

// readLocked reads the table without mutating; caller must hold t.mu.
// A missing table (or state root) is NOT an error for a read-only query:
// it simply means nothing was ever allocated.
func (t *Table) readLocked() (*diskState, error) {
	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &diskState{Allocations: map[string]uint32{}}, nil
		}
		return nil, fmt.Errorf("uidalloc: open table: %w", err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
		return nil, fmt.Errorf("uidalloc: lock table: %w", err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return decode(f)
}

func decode(f *os.File) (*diskState, error) {
	st := &diskState{Allocations: map[string]uint32{}}
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("uidalloc: stat table: %w", err)
	}
	if fi.Size() == 0 {
		return st, nil
	}
	if err := json.NewDecoder(f).Decode(st); err != nil {
		return nil, fmt.Errorf("uidalloc: corrupt table %s: %w", f.Name(), err)
	}
	if st.Allocations == nil {
		st.Allocations = map[string]uint32{}
	}
	return st, nil
}

func write(f *os.File, st *diskState) error {
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("uidalloc: encode table: %w", err)
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("uidalloc: truncate table: %w", err)
	}
	if _, err := f.WriteAt(blob, 0); err != nil {
		return fmt.Errorf("uidalloc: write table: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("uidalloc: fsync table: %w", err)
	}
	return nil
}
