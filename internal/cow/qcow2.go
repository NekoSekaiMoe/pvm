// qcow2.go is a minimal, pure-Go implementation of the two qcow2 operations
// PVM needs, replacing the qemu-img subprocess dependency:
//
//   - createQcow2:  an empty qcow2 v3 image, optionally backed by a base
//     image (raw or qcow2) — replaces `qemu-img create -f
//     qcow2 -b <base> -F <fmt>`.
//   - convertToRaw: flatten an overlay chain into a standalone raw image —
//     replaces `qemu-img convert -O raw`.
//
// Only the subset of the format PVM produces/consumes is supported:
// standard (uncompressed) clusters, no snapshots, no extended L2, no LUKS.
// Compressed clusters (never produced by our create path nor by
// qemu-storage-daemon serving our overlays) are rejected with a clear error.
//
// Format reference: docs/interop/qcow2.txt in the QEMU tree. All on-disk
// fields are big-endian.
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

const (
	qcow2Version3    = 3
	qcow2HeaderLen   = 112 // v3 fixed header (104) + end-of-extensions area
	clusterBits      = 16  // 64 KiB clusters, same as qemu-img default
	clusterSize      = 1 << clusterBits
	refcountOrder    = 4 // 2^4 = 16-bit refcount entries (qemu-img default)
	extBackingFormat = 0xE2792ACA

	oflagCopied     = 1 << 63
	oflagCompressed = 1 << 62
	oflagZero       = 1 << 0

	// Standard-cluster offset masks (block/qcow2.h L1E/L2E_OFFSET_MASK).
	l1eOffsetMask = 0x00fffffffffffe00
	l2eOffsetMask = 0x00fffffffffffe00
)

// qcow2Header mirrors the on-disk v3 header layout.
type qcow2Header struct {
	size             uint64 // virtual disk size
	backingFile      string
	l1Offset         uint64
	l1Size           uint32
	refcountOffset   uint64
	refcountClusters uint32
}

// createQcow2 writes an empty qcow2 v3 image at path with the given virtual
// size. If backingPath is non-empty the image is an overlay: every cluster
// reads through to backingPath (format backingFormat: "raw" or "qcow2")
// until written. backingPath is stored as given (callers pass an absolute
// path so the reference is unambiguous).
func createQcow2(path string, virtualSize uint64, backingPath, backingFormat string) error {
	if virtualSize == 0 {
		return errors.New("cow: qcow2 virtual size must be > 0")
	}
	// L1 coverage: one L2 table holds clusterSize/8 = 8192 entries, each
	// covering one 64 KiB cluster => 512 MiB of guest data per L1 entry.
	l2Entries := uint64(clusterSize / 8)
	l1Size := (virtualSize + l2Entries*clusterSize - 1) / (l2Entries * clusterSize)
	l1Clusters := (l1Size*8 + clusterSize - 1) / clusterSize

	// Fixed metadata layout, one cluster each unless L1 needs more:
	//   cluster 0: header (+ extensions + backing file name)
	//   cluster 1: refcount table (8192 u64 entries)
	//   cluster 2: refcount block 0 (32768 u16 entries => covers 32K clusters)
	//   cluster 3..: L1 table
	refTableOff := uint64(clusterSize)
	refBlockOff := uint64(2 * clusterSize)
	l1Off := uint64(3 * clusterSize)
	nMeta := 3 + l1Clusters
	// A single refcount block covers 32768 clusters; L1 would need to describe
	// a > 16 TiB image before metadata outgrows it. Guard anyway.
	if nMeta > 32768 {
		return fmt.Errorf("cow: image too large for single refcount block (%d meta clusters)", nMeta)
	}

	buf := make([]byte, nMeta*clusterSize)

	// --- header (cluster 0) ---
	hdr := buf[:qcow2HeaderLen]
	copy(hdr[0:4], qcow2Magic)
	binary.BigEndian.PutUint32(hdr[4:], qcow2Version3)
	binary.BigEndian.PutUint32(hdr[0x14:], clusterBits)
	binary.BigEndian.PutUint64(hdr[0x18:], virtualSize)
	// crypt_method (0x20) stays 0 (no encryption)
	binary.BigEndian.PutUint32(hdr[0x24:], uint32(l1Size))
	binary.BigEndian.PutUint64(hdr[0x28:], l1Off)
	binary.BigEndian.PutUint64(hdr[0x30:], refTableOff)
	binary.BigEndian.PutUint32(hdr[0x38:], 1) // refcount_table_clusters
	// nb_snapshots / snapshots_offset stay 0
	// incompatible/compatible/autoclear features stay 0
	binary.BigEndian.PutUint32(hdr[0x60:], refcountOrder)
	binary.BigEndian.PutUint32(hdr[0x64:], qcow2HeaderLen)

	// --- header extensions + backing file name (also in cluster 0) ---
	off := uint64(qcow2HeaderLen)
	if backingPath != "" {
		// Backing format name extension, like qemu-img stores for -F. Without
		// it consumers would have to probe the (untrusted) backing content.
		name := backingFormat
		binary.BigEndian.PutUint32(buf[off:], extBackingFormat)
		binary.BigEndian.PutUint32(buf[off+4:], uint32(len(name)))
		copy(buf[off+8:], name)
		off += 8 + roundUp8(uint64(len(name)))
	}
	// end-of-extensions marker: magic 0, length 0 (already zeroed)
	off += 8
	if backingPath != "" {
		if len(backingPath) > 4096 || off+uint64(len(backingPath)) > clusterSize {
			return fmt.Errorf("cow: backing path too long for qcow2 header cluster")
		}
		binary.BigEndian.PutUint64(buf[0x08:], off)
		binary.BigEndian.PutUint32(buf[0x10:], uint32(len(backingPath)))
		copy(buf[off:], backingPath)
	}

	// --- refcount table (cluster 1): entry 0 -> refcount block 0 ---
	binary.BigEndian.PutUint64(buf[refTableOff:], refBlockOff)

	// --- refcount block 0 (cluster 2): metadata clusters have refcount 1 ---
	for i := uint64(0); i < nMeta; i++ {
		binary.BigEndian.PutUint16(buf[refBlockOff+2*i:], 1)
	}

	// --- L1 table (cluster 3..): all zero = every cluster reads from backing ---

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cow: create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("cow: write qcow2 metadata: %w", err)
	}
	return nil
}

func roundUp8(v uint64) uint64 { return (v + 7) &^ 7 }

// ---------------------------------------------------------------------------
// Reading (for convertToRaw)
// ---------------------------------------------------------------------------

// guestImage is anything that can serve guest-offset reads: a raw file or a
// parsed qcow2 (which falls through to its backing chain).
type guestImage interface {
	io.ReaderAt // ReadAt reads at a GUEST offset; short reads at EOF return io.EOF
	Size() uint64
	Close() error
}

type rawImage struct {
	f    *os.File
	size uint64
}

func (r *rawImage) ReadAt(p []byte, off int64) (int, error) { return r.f.ReadAt(p, off) }
func (r *rawImage) Size() uint64                            { return r.size }
func (r *rawImage) Close() error                            { return r.f.Close() }

type qcow2Image struct {
	f           *os.File
	hdr         qcow2Header
	backing     guestImage // nil for standalone images
	clusterMask uint64
}

func (q *qcow2Image) Size() uint64 { return q.hdr.size }
func (q *qcow2Image) Close() error {
	err := q.f.Close()
	if q.backing != nil {
		if berr := q.backing.Close(); err == nil {
			err = berr
		}
	}
	return err
}

// ReadAt reads guest data at off, resolving L1/L2 mappings and falling
// through to the backing chain for unallocated clusters.
func (q *qcow2Image) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for total < len(p) {
		guest := uint64(off) + uint64(total)
		if guest >= q.hdr.size {
			return total, io.EOF
		}
		host, fromBacking, n, err := q.resolve(guest, uint64(len(p))-uint64(total))
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrUnexpectedEOF
		}
		if host == hostZero {
			// zero cluster: leave p as-is (callers pass zeroed or we zero it)
			zero := p[total : total+int(n)]
			for i := range zero {
				zero[i] = 0
			}
		} else if fromBacking {
			m, err := q.backing.ReadAt(p[total:total+int(n)], int64(guest))
			if err != nil && err != io.EOF {
				return total, err
			}
			if m < int(n) {
				// backing shorter than the overlay's virtual size: rest is zero
				zero := p[total+m : total+int(n)]
				for i := range zero {
					zero[i] = 0
				}
			}
		} else {
			if _, err := q.f.ReadAt(p[total:total+int(n)], int64(host)); err != nil {
				return total, err
			}
		}
		total += int(n)
	}
	return total, nil
}

const hostZero = ^uint64(0) // sentinel: cluster reads as zero

// resolve maps a guest offset to a host file offset. It returns
// (hostZero, false, n) for zero clusters, or (0, true, n) when the data must
// come from the backing chain. n is the number of bytes resolvable within
// the current cluster.
func (q *qcow2Image) resolve(guest, want uint64) (host uint64, fromBacking bool, n uint64, err error) {
	clusterIdx := guest >> clusterBits
	inCluster := guest & q.clusterMask
	n = clusterSize - inCluster
	if want < n {
		n = want
	}
	l1Idx := clusterIdx / (clusterSize / 8)
	l2Idx := clusterIdx % (clusterSize / 8)
	if l1Idx >= uint64(q.hdr.l1Size) {
		return 0, false, 0, fmt.Errorf("cow: guest offset %#x beyond L1 table", guest)
	}
	var l1e uint64
	if err := q.readUint64At(&l1e, q.hdr.l1Offset+l1Idx*8); err != nil {
		return 0, false, 0, err
	}
	l2Off := l1e & l1eOffsetMask
	if l2Off == 0 {
		return q.backingOrZero(guest, n)
	}
	var l2e uint64
	if err := q.readUint64At(&l2e, l2Off+l2Idx*8); err != nil {
		return 0, false, 0, err
	}
	if l2e&oflagCompressed != 0 {
		return 0, false, 0, fmt.Errorf("cow: compressed qcow2 clusters unsupported (guest offset %#x)", guest)
	}
	host = l2e & l2eOffsetMask
	if host == 0 {
		// Fully unallocated entry: backing (or zero). A ZERO-flagged entry
		// with no host offset reads as zero without consulting the backing.
		if l2e&oflagZero != 0 {
			return hostZero, false, n, nil
		}
		return q.backingOrZero(guest, n)
	}
	if l2e&oflagZero != 0 {
		return hostZero, false, n, nil
	}
	return host + inCluster, false, n, nil
}

func (q *qcow2Image) backingOrZero(guest, n uint64) (uint64, bool, uint64, error) {
	if q.backing == nil {
		return hostZero, false, n, nil
	}
	return 0, true, n, nil
}

func (q *qcow2Image) readUint64At(dst *uint64, off uint64) error {
	var b [8]byte
	if _, err := q.f.ReadAt(b[:], int64(off)); err != nil {
		return fmt.Errorf("cow: read qcow2 table at %#x: %w", off, err)
	}
	*dst = binary.BigEndian.Uint64(b[:])
	return nil
}

// openGuestImage sniffs the magic and opens path as raw or qcow2, opening
// the backing chain recursively. baseDir resolves relative backing names the
// way qcow2 specifies: relative to the image's own directory.
func openGuestImage(path string) (guestImage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("cow: read magic of %s: %w", path, err)
	}
	if string(magic[:]) != qcow2Magic {
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		return &rawImage{f: f, size: uint64(st.Size())}, nil
	}

	var hdrBuf [qcow2HeaderLen]byte
	if _, err := f.ReadAt(hdrBuf[:], 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("cow: read qcow2 header of %s: %w", path, err)
	}
	if v := binary.BigEndian.Uint32(hdrBuf[4:]); v != qcow2Version3 {
		f.Close()
		return nil, fmt.Errorf("cow: unsupported qcow2 version %d in %s (want 3)", v, path)
	}
	if cb := binary.BigEndian.Uint32(hdrBuf[0x14:]); cb != clusterBits {
		f.Close()
		return nil, fmt.Errorf("cow: unsupported cluster_bits %d in %s (want %d)", cb, path, clusterBits)
	}
	if cm := binary.BigEndian.Uint32(hdrBuf[0x20:]); cm != 0 {
		f.Close()
		return nil, fmt.Errorf("cow: encrypted qcow2 (crypt_method=%d) unsupported in %s", cm, path)
	}
	if inc := binary.BigEndian.Uint64(hdrBuf[0x48:]); inc != 0 {
		f.Close()
		return nil, fmt.Errorf("cow: qcow2 incompatible features %#x in %s unsupported", inc, path)
	}
	q := &qcow2Image{f: f, clusterMask: clusterSize - 1}
	q.hdr = qcow2Header{
		size:             binary.BigEndian.Uint64(hdrBuf[0x18:]),
		l1Size:           binary.BigEndian.Uint32(hdrBuf[0x24:]),
		l1Offset:         binary.BigEndian.Uint64(hdrBuf[0x28:]),
		refcountOffset:   binary.BigEndian.Uint64(hdrBuf[0x30:]),
		refcountClusters: binary.BigEndian.Uint32(hdrBuf[0x38:]),
	}
	bfOff := binary.BigEndian.Uint64(hdrBuf[0x08:])
	bfSize := binary.BigEndian.Uint32(hdrBuf[0x10:])
	if bfSize > 0 {
		if bfSize > 4096 {
			f.Close()
			return nil, fmt.Errorf("cow: implausible backing name length %d in %s", bfSize, path)
		}
		name := make([]byte, bfSize)
		if _, err := f.ReadAt(name, int64(bfOff)); err != nil {
			f.Close()
			return nil, fmt.Errorf("cow: read backing name in %s: %w", path, err)
		}
		backingPath := string(name)
		if !filepath.IsAbs(backingPath) {
			backingPath = filepath.Join(filepath.Dir(path), backingPath)
		}
		backing, err := openGuestImage(backingPath)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("cow: open backing of %s: %w", path, err)
		}
		q.backing = backing
	}
	return q, nil
}

// convertToRaw flattens the image (and its backing chain) at srcPath into a
// standalone raw image at destPath. Sparse in, sparse out: regions that are
// zero everywhere are skipped with seeks instead of written.
func convertToRaw(ctx context.Context, srcPath, destPath string) error {
	img, err := openGuestImage(srcPath)
	if err != nil {
		return err
	}
	defer img.Close()

	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cow: create dest: %w", err)
	}
	defer out.Close()

	size := img.Size()
	buf := make([]byte, clusterSize)
	for off := uint64(0); off < size; off += clusterSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := uint64(clusterSize)
		if rem := size - off; rem < n {
			n = rem
		}
		chunk := buf[:n]
		m, err := img.ReadAt(chunk, int64(off))
		if err != nil && err != io.EOF {
			return fmt.Errorf("cow: read guest at %#x: %w", off, err)
		}
		// Tolerated short read (io.EOF): zero the unread tail so stale bytes
		// from the previous iteration are never mistaken for guest data.
		if m < len(chunk) {
			clear(chunk[m:])
		}
		if allZero(chunk) {
			continue // seek past: keeps the raw output sparse
		}
		if _, err := out.WriteAt(chunk, int64(off)); err != nil {
			return fmt.Errorf("cow: write raw at %#x: %w", off, err)
		}
	}
	if err := out.Truncate(int64(size)); err != nil {
		return fmt.Errorf("cow: truncate raw output: %w", err)
	}
	return nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
