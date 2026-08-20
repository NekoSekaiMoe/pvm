// qcow2_compact.go implements in-place compaction of a qcow2 overlay — the
// pure-Go equivalent of `qemu-img convert -O qcow2 src.qcow2 dst.qcow2` (rebuild
// only the allocated clusters into a fresh, minimal image).
//
// Why: the write path (qcow2_write.go) allocates clusters by appending at EOF
// with no free list, and createQcow2 preallocates a worst-case refcount-block
// region plus (optionally) every L2 table. After a sandbox exits its overlay
// therefore carries: every cluster ever written (including ones the guest
// later zeroed), unused preallocated L2 tables, and the worst-case refblock
// region. Compact rebuilds the overlay so it contains only:
//
//   - clusters that hold non-zero data (copied, densely packed);
//   - clusters that read as zero, represented as ZERO-flag L2 entries with no
//     host offset (semantics-preserving: reads return zero and a later write
//     allocates a fresh cluster — the same CoW behavior as before).
//
// Unallocated clusters (never written, or reading through to the backing
// chain) stay unallocated, so reads keep falling through to the same backing.
// The result is byte-for-byte identical to the source for every guest read,
// but physically smaller — which matters for snapshot export (snapshot.Export
// tars the whole container dir) and for state-dir retention.
//
// Safety: Compact must run when no live backend is serving the image. The
// container manager calls it after the guest has exited and the vhost backend
// has been closed. The rebuild writes a sibling temp file and atomically
// renames it over the original, so a crash or failure leaves the original
// overlay untouched.
package cow

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CompactStats reports what a Compact pass did. Sizes are host file sizes
// (logical length; the physical st_blocks saving is typically larger because
// the rebuilt image's zero regions are sparse).
type CompactStats struct {
	BeforeBytes uint64
	AfterBytes  uint64
	// ClustersCopied: data clusters rewritten into the new overlay.
	ClustersCopied int64
	// ClustersZeroed: source clusters (allocated or ZERO-flagged) whose guest
	// view is all zero. Represented as ZERO-flag entries with no host offset.
	ClustersZeroed int64
	// ClustersDropped: source clusters that were unallocated (already reading
	// from the backing chain); they stay unallocated in the new overlay.
	ClustersDropped int64
}

// Compact rebuilds the qcow2 image at overlayFile in place: it rewrites only
// the allocated clusters into a fresh, minimal qcow2, dropping zero clusters
// to ZERO-flag entries and leaving unallocated clusters to fall through to
// the backing chain. The backing reference (path + format) and virtual size
// are preserved.
//
// Compact is the pure-Go analogue of `qemu-img convert -O qcow2` over an
// overlay that keeps its backing file. It requires no qemu binaries.
//
// The caller MUST guarantee no process has the image open for writes (the
// container manager runs it after the guest exits and the vhost backend
// closes). Reads happening concurrently with Compact are NOT safe.
func Compact(ctx context.Context, overlayFile string) (CompactStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var stats CompactStats
	if err := validatePath(overlayFile); err != nil {
		return stats, err
	}
	abs, err := filepath.Abs(overlayFile)
	if err != nil {
		return stats, fmt.Errorf("cow: resolve overlay path: %w", err)
	}
	if !isQcow2(abs) {
		return stats, fmt.Errorf("cow: compact requires a qcow2 image (not raw): %s", abs)
	}
	st0, err := os.Stat(abs)
	if err != nil {
		return stats, fmt.Errorf("cow: stat overlay: %w", err)
	}
	stats.BeforeBytes = uint64(st0.Size())

	src, err := openGuestImage(abs)
	if err != nil {
		return stats, fmt.Errorf("cow: open overlay for compact: %w", err)
	}
	q, ok := src.(*qcow2Image)
	if !ok {
		src.Close()
		return stats, fmt.Errorf("cow: %s sniffed qcow2 but parsed raw", abs)
	}
	if q.hdr.snapshots != 0 || q.hdr.snapshotsOffset != 0 {
		src.Close()
		return stats, fmt.Errorf("cow: compact refuses images with internal snapshots (%d snapshots)", q.hdr.snapshots)
	}
	if q.hdr.size == 0 {
		src.Close()
		return stats, errors.New("cow: compact: image has zero virtual size")
	}

	virtualSize := q.hdr.size
	bits := q.clusterBits
	backingAbs := q.backingAbs
	backingFormat := "raw"
	if backingAbs != "" && isQcow2(backingAbs) {
		backingFormat = "qcow2"
	}

	// Build the replacement into a sibling temp file in the SAME directory so
	// the final rename is atomic on the same filesystem. The name is fixed
	// (validated: no commas/NUL/protocol prefixes) and removed before/after.
	tmp := abs + ".compact.tmp"
	_ = os.Remove(tmp)
	defer func() {
		// Best-effort cleanup if we bail before the rename; after a
		// successful rename tmp no longer exists.
		_ = os.Remove(tmp)
	}()

	// Fresh overlay over the same backing, same geometry, NO preallocated L2
	// tables — we only want to materialize L2 slots we actually fill.
	opt := OverlayOpt{ClusterBits: bits, PreallocMetadata: false}
	if backingAbs != "" {
		if err := createQcow2(tmp, virtualSize, backingAbs, backingFormat, opt); err != nil {
			src.Close()
			return stats, fmt.Errorf("cow: compact: create overlay: %w", err)
		}
	} else {
		if err := createQcow2(tmp, virtualSize, "", "", opt); err != nil {
			src.Close()
			return stats, fmt.Errorf("cow: compact: create standalone image: %w", err)
		}
	}

	w, err := OpenWritable(tmp)
	if err != nil {
		src.Close()
		return stats, fmt.Errorf("cow: compact: open dest: %w", err)
	}
	qw, ok := w.(*qcow2Writable)
	if !ok {
		// OpenWritable returns *qcow2Writable for qcow2 inputs; a raw dest
		// would mean createQcow2 silently produced a raw file, which it
		// cannot. This branch is unreachable but keeps the type assertion
		// honest rather than panicking on a future variant.
		w.Close()
		src.Close()
		return stats, fmt.Errorf("cow: compact: dest is not a qcow2 writable")
	}

	cerr := compactWalk(ctx, q, qw, &stats)

	// Sync before close so the renamed file is durable; close regardless.
	if cerr == nil {
		if err := qw.Sync(); err != nil {
			cerr = fmt.Errorf("cow: compact: sync dest: %w", err)
		}
	}
	w.Close()
	src.Close()
	if cerr != nil {
		return stats, cerr
	}

	st1, err := os.Stat(tmp)
	if err != nil {
		return stats, fmt.Errorf("cow: compact: stat dest: %w", err)
	}
	stats.AfterBytes = uint64(st1.Size())
	if err := os.Rename(tmp, abs); err != nil {
		return stats, fmt.Errorf("cow: compact: rename into place: %w", err)
	}
	return stats, nil
}

// compactWalk iterates the source overlay's L1/L2 tables and copies each live
// cluster into the dest. It is the heart of Compact, factored out so the
// caller handles setup/teardown/cleanup.
//
// Per source L2 entry:
//
//	e & oflagCompressed        -> reject (we never produce these)
//	e & oflagZero (any host)   -> dest ZERO-flag entry (no data cluster)
//	host == 0, zero flag clear -> unallocated; dest stays unallocated (drop)
//	host != 0, zero flag clear -> read cluster data via the source chain;
//	                               if all zero -> dest ZERO-flag entry,
//	                               else dest WriteAt (full-cluster fast path)
//
// Reading through the source chain (not the raw host offset) is deliberate:
// it yields the true guest-visible bytes regardless of how the source stored
// them, so the dest's representation (data cluster vs ZERO flag vs hole) is
// chosen from content — exactly what a semantics-preserving rebuild needs.
func compactWalk(ctx context.Context, src *qcow2Image, dst *qcow2Writable, stats *CompactStats) error {
	cs := src.clusterSize
	l2Entries := cs / 8
	buf := make([]byte, cs)
	l2Table := make([]byte, cs)

	for l1Idx := uint32(0); l1Idx < src.hdr.l1Size; l1Idx++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var l1e uint64
		if err := src.readUint64At(&l1e, src.hdr.l1Offset+uint64(l1Idx)*8); err != nil {
			return fmt.Errorf("read L1[%d]: %w", l1Idx, err)
		}
		l2Off := l1e & l1eOffsetMask
		if l2Off == 0 {
			// Whole L2 table unallocated: every entry reads from backing.
			stats.ClustersDropped += int64(l2Entries)
			continue
		}
		if _, err := src.f.ReadAt(l2Table, int64(l2Off)); err != nil && err != io.EOF {
			return fmt.Errorf("read L2 table at %#x: %w", l2Off, err)
		}
		for j := uint64(0); j < l2Entries; j++ {
			e := binary.BigEndian.Uint64(l2Table[j*8:])
			if e == 0 {
				stats.ClustersDropped++
				continue
			}
			if e&oflagCompressed != 0 {
				return fmt.Errorf("cow: compact: compressed cluster unsupported (L1=%d L2=%d)", l1Idx, j)
			}
			clusterIdx := uint64(l1Idx)*l2Entries + j
			guestOff := clusterIdx << src.clusterBits
			if guestOff >= src.hdr.size {
				// Entry past virtual size: the create path never writes these,
				// but a foreign image could. Preserve by dropping — nothing
				// reads beyond the virtual size anyway.
				stats.ClustersDropped++
				continue
			}
			// ZERO flag (with or without a host offset) reads as zero.
			if e&oflagZero != 0 {
				if err := dst.setL2Entry(clusterIdx, oflagZero); err != nil {
					return fmt.Errorf("set zero L2 entry (cluster %d): %w", clusterIdx, err)
				}
				stats.ClustersZeroed++
				continue
			}
			host := e & l2eOffsetMask
			if host == 0 {
				// Unallocated, no zero flag: reads from backing. Leave dest
				// unallocated so the read falls through identically.
				stats.ClustersDropped++
				continue
			}
			// Allocated data cluster: read its guest-visible content through
			// the chain, then decide data vs zero.
			n := cs
			if rem := src.hdr.size - guestOff; rem < n {
				n = rem
			}
			// ReadAt fills buf[:n] from the merged chain; zero the tail so a
			// short read (shouldn't happen within size, but be safe) can't
			// fool the allZero check with stale bytes.
			clear(buf[n:])
			m, err := src.ReadAt(buf[:n], int64(guestOff))
			if err != nil && err != io.EOF {
				return fmt.Errorf("read source cluster %d: %w", clusterIdx, err)
			}
			if m < int(n) {
				clear(buf[m:n])
			}
			if allZero(buf[:n]) {
				if err := dst.setL2Entry(clusterIdx, oflagZero); err != nil {
					return fmt.Errorf("set zero L2 entry (cluster %d): %w", clusterIdx, err)
				}
				stats.ClustersZeroed++
				continue
			}
			// Full-cluster, cluster-aligned write -> allocDataCluster fast
			// path (no CoW read, since the write covers the whole cluster).
			// A trailing partial cluster (n < cs at the very end of the
			// virtual size) takes the CoW path, which reads the dest backing
			// for the remainder — identical bytes, since dest shares the
			// same backing.
			if _, err := dst.WriteAt(buf[:n], int64(guestOff)); err != nil {
				return fmt.Errorf("write dest cluster %d: %w", clusterIdx, err)
			}
			stats.ClustersCopied++
		}
	}
	return nil
}
