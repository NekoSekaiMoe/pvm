// qcow2_write.go adds the write path to the pure-Go qcow2 implementation:
// allocating data/L2/refcount clusters and performing copy-on-write for
// partial-cluster writes over a backing chain. This is what lets the
// vhost-user-blk server (internal/vhost/vu) accept guest writes without
// qemu-storage-daemon.
//
// Simplicity over performance: allocations always append at EOF (no free
// list), refcounts are read-modify-write per allocation, and a single mutex
// serializes writers (the blk pump is single-goroutine anyway).
package cow

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
)

// WritableBackend is the storage interface the vhost-user-blk device needs.
// Implementations are safe for concurrent use.
type WritableBackend interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Sync() error
	Size() int64
	Close() error
}

// OpenWritable opens path as a writable backend: raw images are used
// directly; qcow2 images get CoW semantics over their backing chain.
func OpenWritable(path string) (WritableBackend, error) {
	if !isQcow2(path) {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		return &rawWritable{rawImage: rawImage{f: f, size: uint64(st.Size())}}, nil
	}
	base, err := openGuestImage(path)
	if err != nil {
		return nil, err
	}
	q, ok := base.(*qcow2Image)
	if !ok {
		base.Close()
		return nil, fmt.Errorf("cow: %s sniffed qcow2 but parsed raw", path)
	}
	// Capture the identity of the READ-ONLY fd before closing it. Reopening
	// the path O_RDWR below races anyone replacing the file (rename/unlink);
	// without this check a swapped-in different image would silently be
	// served with the first file's parsed metadata.
	firstStat, err := q.f.Stat()
	if err != nil {
		q.Close()
		return nil, err
	}
	// Reopen RW (openGuestImage opened O_RDONLY).
	q.f.Close()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if q.backing != nil {
			q.backing.Close()
		}
		return nil, err
	}
	secondStat, err := f.Stat()
	if err != nil || !os.SameFile(firstStat, secondStat) {
		f.Close()
		if q.backing != nil {
			q.backing.Close()
		}
		return nil, fmt.Errorf("cow: %s was replaced between open and reopen (TOCTOU guard)", path)
	}
	q.f = f
	st, err := f.Stat()
	if err != nil {
		q.Close()
		return nil, err
	}
	return &qcow2Writable{qcow2Image: q, fileSize: uint64(st.Size())}, nil
}

type rawWritable struct{ rawImage }

func (r *rawWritable) WriteAt(p []byte, off int64) (int, error) { return r.f.WriteAt(p, off) }
func (r *rawWritable) Sync() error                              { return r.f.Sync() }
func (r *rawWritable) Size() int64                              { return int64(r.size) }

// qcow2Writable adds CoW writes to a parsed qcow2 image.
type qcow2Writable struct {
	*qcow2Image
	mu       sync.Mutex
	fileSize uint64 // current host file size; allocations append here
}

func (w *qcow2Writable) Size() int64 { return int64(w.hdr.size) }
func (w *qcow2Writable) Sync() error { return w.f.Sync() }

// ReadAt serializes with WriteAt under w.mu so a concurrent reader never
// observes half-updated L1/L2 or refcount metadata.
func (w *qcow2Writable) ReadAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.qcow2Image.ReadAt(p, off)
}

// WriteAt writes at a guest offset, allocating clusters on first write and
// copying backing content for partial-cluster writes (qcow2 CoW).
func (w *qcow2Writable) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cs := w.clusterSize
	total := 0
	for total < len(p) {
		guest := uint64(off) + uint64(total)
		if guest >= w.hdr.size {
			return total, fmt.Errorf("cow: write beyond virtual size (%#x >= %#x)", guest, w.hdr.size)
		}
		clusterIdx := guest >> w.clusterBits
		inCluster := guest & w.clusterMask
		n := cs - inCluster
		if rem := uint64(len(p)) - uint64(total); rem < n {
			n = rem
		}
		host, err := w.hostOffset(clusterIdx)
		if err != nil {
			return total, err
		}
		if host == 0 {
			// Unallocated (or zero) cluster: allocate + COW.
			fullCluster := inCluster == 0 && n == cs
			host, err = w.allocDataCluster(clusterIdx, p[total:total+int(n)], guest, fullCluster)
			if err != nil {
				return total, err
			}
			total += int(n)
			continue
		}
		if _, err := w.f.WriteAt(p[total:total+int(n)], int64(host+inCluster)); err != nil {
			return total, err
		}
		total += int(n)
	}
	return total, nil
}

// hostOffset returns the host file offset of a guest cluster's start, or 0
// when the cluster is unallocated/zero (reads fall through to backing).
func (w *qcow2Writable) hostOffset(clusterIdx uint64) (uint64, error) {
	l2Entries := w.clusterSize / 8
	l1Idx := clusterIdx / l2Entries
	l2Idx := clusterIdx % l2Entries
	l1e, err := w.l1Entry(l1Idx)
	if err != nil {
		return 0, fmt.Errorf("cow: guest cluster %d beyond L1", clusterIdx)
	}
	l2Off := l1e & l1eOffsetMask
	if l2Off == 0 {
		return 0, nil
	}
	l2e, err := w.l2EntryAt(l2Off, l2Idx)
	if err != nil {
		return 0, err
	}
	if l2e&oflagCompressed != 0 {
		return 0, fmt.Errorf("cow: compressed clusters unsupported")
	}
	// Only clusters we fully own (COPIED set, ZERO clear) may be written in
	// place. A ZERO-flagged entry reads as all zeros even when it carries a
	// host offset (preallocation), so an in-place write would be invisible
	// to resolve(); a non-COPIED entry may share its cluster (refcount > 1),
	// so an in-place write would corrupt the shared data. Treat both as
	// unallocated: WriteAt allocates a fresh cluster and linkL2 installs a
	// new COPIED entry, clearing ZERO.
	if l2e&(oflagCopied|oflagZero) != oflagCopied {
		return 0, nil
	}
	return l2e & l2eOffsetMask, nil
}

// allocDataCluster allocates a host cluster for guest cluster clusterIdx,
// performs copy-on-write of the backing content when the write doesn't cover
// the whole cluster, and links the L2 entry.
func (w *qcow2Writable) allocDataCluster(clusterIdx uint64, data []byte, guest uint64, fullCluster bool) (uint64, error) {
	hostOff, err := w.allocCluster()
	if err != nil {
		return 0, err
	}
	if fullCluster {
		if _, err := w.f.WriteAt(data, int64(hostOff)); err != nil {
			return 0, err
		}
	} else {
		// CoW: materialize the backing view of this cluster, then overlay
		// the partial write. The final cluster may extend past the virtual
		// size: read only what exists (a short read at EOF leaves the rest
		// of buf zeroed).
		cs := w.clusterSize
		buf := make([]byte, cs)
		clusterStart := int64(clusterIdx << w.clusterBits)
		readLen := int64(cs)
		if rem := int64(w.hdr.size) - clusterStart; rem < readLen {
			readLen = rem
		}
		if readLen > 0 {
			if _, err := w.qcow2Image.ReadAt(buf[:readLen], clusterStart); err != nil && err != io.EOF {
				return 0, fmt.Errorf("cow: read backing for CoW at %#x: %w", clusterStart, err)
			}
		}
		inCluster := guest & w.clusterMask
		copy(buf[inCluster:], data)
		if _, err := w.f.WriteAt(buf, int64(hostOff)); err != nil {
			return 0, err
		}
	}
	if err := w.linkL2(clusterIdx, hostOff); err != nil {
		return 0, err
	}
	return hostOff, nil
}

// setL2Entry points the L2 entry for clusterIdx at the raw l2e value,
// allocating the L2 table first if needed. host clusters referenced by
// l2e must already be refcounted by the caller; a bare oflagZero entry
// ("cluster reads as zero, no host offset") references nothing and needs no
// refcount — that is the compact path's zero-cluster representation.
func (w *qcow2Writable) setL2Entry(clusterIdx, l2e uint64) error {
	l2Entries := w.clusterSize / 8
	l1Idx := clusterIdx / l2Entries
	l2Idx := clusterIdx % l2Entries
	if l1Idx >= uint64(len(w.l1)) {
		return fmt.Errorf("cow: guest cluster %d beyond L1", clusterIdx)
	}
	l1e := w.l1[l1Idx]
	l2Off := l1e & l1eOffsetMask
	if l2Off == 0 {
		var err error
		l2Off, err = w.allocCluster()
		if err != nil {
			return err
		}
		// Fresh L2 table: zero it, refcount 1, link L1.
		if _, err := w.f.WriteAt(make([]byte, w.clusterSize), int64(l2Off)); err != nil {
			return err
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], l2Off|oflagCopied)
		if _, err := w.f.WriteAt(b[:], int64(w.hdr.l1Offset+l1Idx*8)); err != nil {
			return err
		}
		// Keep the in-memory L1 copy in sync with the disk write above.
		w.l1[l1Idx] = l2Off | oflagCopied
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], l2e)
	if _, err := w.f.WriteAt(b[:], int64(l2Off+l2Idx*8)); err != nil {
		return err
	}
	// Write-through: mirror the new entry into the cached L2 table (if that
	// table is cached) so reads never see a stale mapping.
	w.updateL2Cache(l2Off, l2Idx, l2e)
	return nil
}

// linkL2 points the L2 entry for clusterIdx at hostOff (a freshly allocated,
// refcount-1 data cluster) with the COPIED flag set. It is the normal
// allocate-on-write path; setL2Entry is the general form used by compact.
func (w *qcow2Writable) linkL2(clusterIdx, hostOff uint64) error {
	return w.setL2Entry(clusterIdx, hostOff|oflagCopied)
}

// allocCluster appends a cluster's worth of space at EOF and sets its
// refcount to 1. Returns the host offset.
//
// The cluster is NOT pre-zeroed on disk: the space becomes a sparse hole that
// reads as zeros, which is exactly what the previous explicit zero-fill
// produced, minus one full-cluster write per allocation (2x write amplification
// removed for the common allocate-then-overwrite paths). Crash consistency is
// unchanged: every caller writes the FULL cluster content BEFORE linking it —
// allocDataCluster writes whole clusters (direct or CoW-materialized),
// setL2Entry zero-fills fresh L2 tables — so an unlinked cluster is never
// reachable through resolve() (its L2 entry is still unallocated), and once
// linked its bytes are already in place. bumpRefcount's refcount blocks rely
// on hole-reads-as-zeros for their untouched entries, identical to reading
// back the old zero-filled blocks.
func (w *qcow2Writable) allocCluster() (uint64, error) {
	cs := w.clusterSize
	off := w.fileSize
	if off%cs != 0 {
		return 0, fmt.Errorf("cow: host file size %#x not cluster-aligned", off)
	}
	w.fileSize += cs
	// Keep the read-side bound (qcow2Image.fileSize, captured at open) in
	// step with the grown file: l2EntryAt validates L2 offsets against it,
	// and a freshly allocated L2 table legitimately lives at the old EOF.
	w.qcow2Image.fileSize = w.fileSize
	if err := w.bumpRefcount(off >> w.clusterBits); err != nil {
		return 0, err
	}
	return off, nil
}

// bumpRefcount sets refcount(clusterIdx) = 1, allocating additional refcount
// blocks (registered in the refcount table) when the image grows past what
// the existing blocks cover. The refcount table itself is fixed at create
// time (its size covers the image's worst case).
func (w *qcow2Writable) bumpRefcount(clusterIdx uint64) error {
	entriesPerBlock := w.clusterSize / 2 // u16 entries per refcount block
	// Overflow-safe bounds check: blockIdx must stay below the number of
	// entries the reftable can hold. Computing maxBlocks*entriesPerBlock as
	// a ceiling can wrap for large refcountClusters/clusterSize combinations
	// (both attacker-controlled in foreign images), so divide instead:
	// maxBlocks = refcountClusters * cs/8 may itself overflow only past 2^64,
	// and the per-iteration check below re-validates with the same value.
	maxBlocks := uint64(w.hdr.refcountClusters) * (w.clusterSize / 8)
	if maxBlocks != 0 && clusterIdx/entriesPerBlock >= maxBlocks {
		return fmt.Errorf("cow: refcount table full at cluster %d", clusterIdx)
	}
	// Register refcount blocks iteratively instead of recursively: a freshly
	// registered block's own cluster needs a refcount too, which may fall in
	// a block that doesn't exist yet. deferred mirrors the call stack the
	// recursion would build: each pending cluster's entry is written after
	// the blocks it depends on are registered (its own blockOff, re-read on
	// the way back, is non-zero by then). Termination: a new block is
	// appended at EOF, so its self-cluster index is strictly larger than
	// any cluster seen so far, bounded by the per-iteration table check.
	var deferred []uint64
	idx := clusterIdx
	for {
		blockIdx := idx / entriesPerBlock
		if blockIdx >= maxBlocks {
			return fmt.Errorf("cow: refcount table full at cluster %d", idx)
		}
		var tableEntry uint64
		if err := w.readUint64At(&tableEntry, w.hdr.refcountOffset+blockIdx*8); err != nil {
			return err
		}
		blockOff := tableEntry & reftOffsetMask // REFT_OFFSET_MASK
		if blockOff == 0 {
			// Allocate a new refcount block at EOF and register it in the table.
			blockOff = w.fileSize
			if _, err := w.f.WriteAt(make([]byte, w.clusterSize), int64(blockOff)); err != nil {
				return err
			}
			w.fileSize += w.clusterSize
			w.qcow2Image.fileSize = w.fileSize // keep read-side bounds in sync (see allocCluster)
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], blockOff)
			if _, err := w.f.WriteAt(b[:], int64(w.hdr.refcountOffset+blockIdx*8)); err != nil {
				return err
			}
			// The new block's own cluster also needs refcount 1; it is larger
			// than idx, so register its block first and come back for idx.
			if selfCluster := blockOff >> w.clusterBits; selfCluster != idx {
				deferred = append(deferred, idx)
				idx = selfCluster
				continue
			}
		}
		var c [2]byte
		binary.BigEndian.PutUint16(c[:], 1)
		if _, err := w.f.WriteAt(c[:], int64(blockOff+(idx%entriesPerBlock)*2)); err != nil {
			return err
		}
		if len(deferred) == 0 {
			return nil
		}
		idx, deferred = deferred[len(deferred)-1], deferred[:len(deferred)-1]
	}
}
