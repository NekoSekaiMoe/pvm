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
	clusterBits      = 12  // 4 KiB clusters (default): matches ext4 block size
	clusterSize      = 1 << clusterBits
	refcountOrder    = 4 // 2^4 = 16-bit refcount entries (qemu-img default)
	extBackingFormat = 0xE2792ACA

	oflagCopied     = 1 << 63
	oflagCompressed = 1 << 62
	oflagZero       = 1 << 0

	// Standard-cluster offset masks (block/qcow2.h L1E/L2E_OFFSET_MASK).
	l1eOffsetMask = 0x00fffffffffffe00
	l2eOffsetMask = 0x00fffffffffffe00

	// Refcount table entry mask (qcow2 REFT_OFFSET_MASK): offsets are
	// cluster-aligned so this holds for any cluster size >= 512.
	reftOffsetMask = 0xfffffffffffffe00
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

// OverlayOpt configures qcow2 overlay creation.
type OverlayOpt struct {
	// ClusterBits sets the qcow2 cluster size to 2^bits bytes (512 B .. 2 MiB,
	// the qcow2-spec range). 0 means the package default (4 KiB).
	//
	// 4 KiB matches the ext4 block size and the 4 KiB guest page size, so a
	// guest page-aligned write covers exactly one cluster: the write path
	// stores pure data with no read-modify-write of the tail. With the old
	// 64 KiB default every 4 KiB random write forced a 60 KiB backing read
	// plus a 64 KiB allocation (15x write amplification).
	ClusterBits uint32
	// PreallocMetadata allocates and links every L2 table (and the refcount
	// blocks covering them) at create time, like `qemu-img create
	// preallocation=metadata`. First writes then cost one data-cluster
	// allocation and nothing else — no L2 allocation, no refcount-block
	// allocation, no distributed metadata lock-and-flush. Cost: virtualSize /
	// (clusterSize/8 * clusterSize) bytes of L2 tables upfront (4 KiB
	// clusters: 2 MiB of guest coverage per 4 KiB L2 table = 0.2% of the
	// virtual size).
	PreallocMetadata bool
}

// defaultOverlayOpt is what CreateOverlay (the no-options entry point) uses.
var defaultOverlayOpt = OverlayOpt{ClusterBits: clusterBits, PreallocMetadata: true}

// qcow2Layout is the create-time physical metadata plan for an image.
type qcow2Layout struct {
	clusterBits uint32
	clusterSize uint64
	l1Size      uint64 // L1 entries (one per L2 table)
	l1Clusters  uint64
	l2Count     uint64 // L2 tables written at create (0 unless prealloc)
	reftableCls uint64 // refcount table clusters
	refblockCnt uint64 // refcount blocks sized into the region (worst case)
	refUsedCls  uint64 // refcount-block clusters carrying nonzero entries
	physMeta    uint64 // total physical metadata clusters at create
	reftableOff uint64
	refblockOff uint64
	l1Off       uint64
	l2Off       uint64 // first L2 table (== end of metadata when !prealloc)
}

// computeQcow2Layout sizes the metadata for virtualSize.
//
// The refcount TABLE is sized for the worst case (every data cluster
// allocated) because the write path cannot grow it: bumpRefcount allocates
// refcount BLOCKS lazily, but the table itself is fixed at create. The block
// count written at create only covers the create-time metadata; blocks for
// data clusters appear lazily via bumpRefcount, exactly like before.
func computeQcow2Layout(virtualSize uint64, bits uint32, prealloc bool) (*qcow2Layout, error) {
	if bits == 0 {
		bits = clusterBits
	}
	if bits < 9 || bits > 21 {
		return nil, fmt.Errorf("cow: cluster_bits %d out of qcow2 range 9..21", bits)
	}
	cs := uint64(1) << bits
	l2Entries := cs / 8
	l1Size := (virtualSize + l2Entries*cs - 1) / (l2Entries * cs)
	if l1Size > 0xFFFFFFFF {
		return nil, fmt.Errorf("cow: L1 table too large for virtual size %d", virtualSize)
	}
	l1Clusters := (l1Size*8 + cs - 1) / cs
	var l2Count uint64
	if prealloc {
		l2Count = l1Size
	}
	dataClusters := (virtualSize + cs - 1) / cs

	// Refblocks are preallocated for the WORST CASE (every data cluster
	// allocated): 0.05% of the virtual size at 4 KiB clusters. Without this,
	// the first write into each 8 MiB of new data lazily allocates a refcount
	// block — a distributed metadata update exactly like the L2 allocation
	// this preallocation exists to remove. The fixed point converges because
	// physMeta (hence nbW) grows far slower than refblockCnt each round.
	refblockCnt, reftableCls := uint64(1), uint64(1)
	for i := 0; i < 32; i++ {
		physMeta := 1 + reftableCls + refblockCnt + l1Clusters + l2Count
		worst := physMeta + dataClusters
		nbW := (worst + cs/2 - 1) / (cs / 2) // blocks covering worst case
		nt := (nbW + cs/8 - 1) / (cs / 8)    // table clusters covering worst case
		if nbW == refblockCnt && nt == reftableCls {
			l := &qcow2Layout{
				clusterBits: bits, clusterSize: cs,
				l1Size: l1Size, l1Clusters: l1Clusters, l2Count: l2Count,
				reftableCls: reftableCls, refblockCnt: refblockCnt,
				physMeta: physMeta,
			}
			// Only the first 2*physMeta bytes of the refblock region are
			// nonzero (one u16 per create-time metadata cluster); the rest is
			// streamed zeros at write time.
			l.refUsedCls = (2*physMeta + cs - 1) / cs
			l.reftableOff = cs
			l.refblockOff = (1 + reftableCls) * cs
			l.l1Off = l.refblockOff + refblockCnt*cs
			l.l2Off = l.l1Off + l1Clusters*cs
			return l, nil
		}
		refblockCnt, reftableCls = nbW, nt
	}
	return nil, fmt.Errorf("cow: metadata layout did not converge for virtual size %d", virtualSize)
}

// createQcow2 writes an empty qcow2 v3 image at path with the given virtual
// size. If backingPath is non-empty the image is an overlay: every cluster
// reads through to backingPath (format backingFormat: "raw" or "qcow2")
// until written. backingPath is stored as given (callers pass an absolute
// path so the reference is unambiguous).
func createQcow2(path string, virtualSize uint64, backingPath, backingFormat string, opt OverlayOpt) error {
	if virtualSize == 0 {
		return errors.New("cow: qcow2 virtual size must be > 0")
	}
	lay, err := computeQcow2Layout(virtualSize, opt.ClusterBits, opt.PreallocMetadata)
	if err != nil {
		return err
	}
	cs := lay.clusterSize

	// Only the USED prefix of the refcount-block region carries data (one
	// u16 set to 1 per create-time metadata cluster); everything through
	// that prefix — header cluster, refcount table, refcount blocks — is
	// built in one buffer. The unused refblock remainder and the
	// (optional) preallocated L2 tables are all zeros and are streamed
	// instead: a 1 TiB image at 4 KiB clusters has 128K refblocks = 512 MiB
	// (and 2 GiB of L2) that must never sit in memory.
	buf := make([]byte, lay.refblockOff+lay.refUsedCls*cs)

	// --- header (cluster 0) ---
	hdr := buf[:qcow2HeaderLen]
	copy(hdr[0:4], qcow2Magic)
	binary.BigEndian.PutUint32(hdr[4:], qcow2Version3)
	binary.BigEndian.PutUint32(hdr[0x14:], lay.clusterBits)
	binary.BigEndian.PutUint64(hdr[0x18:], virtualSize)
	// crypt_method (0x20) stays 0 (no encryption)
	binary.BigEndian.PutUint32(hdr[0x24:], uint32(lay.l1Size))
	binary.BigEndian.PutUint64(hdr[0x28:], lay.l1Off)
	binary.BigEndian.PutUint64(hdr[0x30:], lay.reftableOff)
	binary.BigEndian.PutUint32(hdr[0x38:], uint32(lay.reftableCls))
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
		if len(backingPath) > 4096 || off+uint64(len(backingPath)) > cs {
			return fmt.Errorf("cow: backing path too long for qcow2 header cluster: path length %d, header extensions end at %d, cluster size %d", len(backingPath), off, cs)
		}
		binary.BigEndian.PutUint64(buf[0x08:], off)
		binary.BigEndian.PutUint32(buf[0x10:], uint32(len(backingPath)))
		copy(buf[off:], backingPath)
	}

	// --- refcount table: entry b -> refcount block b ---
	for b := uint64(0); b < lay.refblockCnt; b++ {
		binary.BigEndian.PutUint64(buf[lay.reftableOff+b*8:], lay.refblockOff+b*cs)
	}

	// --- refcount blocks: every create-time metadata cluster has count 1.
	// Blocks are contiguous, so a flat fill works: entry i lands in block
	// i/(cs/2) at byte refblockOff + i*2 regardless of block boundaries. ---
	for i := uint64(0); i < lay.physMeta; i++ {
		binary.BigEndian.PutUint16(buf[lay.refblockOff+2*i:], 1)
	}

	// --- L1 table: preallocated L2 tables are linked up front (COPIED set,
	// refcount 1 — qemu-img check requires the flag on refcount-1 entries);
	// otherwise all zero = every cluster reads from backing. Written after
	// the zero-streamed refblock remainder, one cluster at a time. ---

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cow: create %s: %w", path, err)
	}
	defer f.Close()
	// All writes are sequential: the buffer (header..used refblocks), zeros
	// up to l1Off, the L1 table, then the preallocated L2 tables.
	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("cow: write qcow2 metadata: %w", err)
	}
	zero := make([]byte, 1<<20)
	if cs < uint64(len(zero)) {
		zero = zero[:cs]
	}
	if err := streamZeros(f, zero, lay.l1Off-uint64(len(buf)), "zero-fill refcount blocks"); err != nil {
		return err
	}
	entriesPerCluster := cs / 8
	for k := uint64(0); k < lay.l1Clusters; k++ {
		l1 := make([]byte, cs)
		for j := uint64(0); j < entriesPerCluster; j++ {
			if e := k*entriesPerCluster + j; e < lay.l2Count {
				host := lay.l2Off + e*cs
				binary.BigEndian.PutUint64(l1[j*8:], host|oflagCopied)
			}
		}
		if _, err := f.Write(l1); err != nil {
			return fmt.Errorf("cow: write L1 table: %w", err)
		}
	}
	// Preallocated L2 tables are all zeros; stream them (a 1 TiB image at
	// 4 KiB clusters has 512K L2 tables = 2 GiB — never buffer that).
	return streamZeros(f, zero, lay.l2Count*cs, "preallocated L2 tables")
}

// streamZeros writes rem zero bytes sequentially to f in chunks of buf,
// so only the 1 MiB chunk buffer (never the full hundreds-of-MiB region)
// sits in memory.
func streamZeros(f *os.File, buf []byte, rem uint64, what string) error {
	for rem > 0 {
		n := uint64(len(buf))
		if rem < n {
			n = rem
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return fmt.Errorf("cow: write %s: %w", what, err)
		}
		rem -= n
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
	f   *os.File
	hdr qcow2Header
	// Cluster geometry is per-image (cluster_bits lives in the header at
	// 0x14); images we created with other cluster sizes — or foreign images —
	// must read with THEIR geometry, not the package default.
	clusterBits uint32
	clusterSize uint64
	clusterMask uint64
	backing     guestImage // nil for standalone images
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
	clusterIdx := guest >> q.clusterBits
	inCluster := guest & q.clusterMask
	n = q.clusterSize - inCluster
	if want < n {
		n = want
	}
	l2Entries := q.clusterSize / 8
	l1Idx := clusterIdx / l2Entries
	l2Idx := clusterIdx % l2Entries
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
	cb := binary.BigEndian.Uint32(hdrBuf[0x14:])
	if cb < 9 || cb > 21 {
		f.Close()
		return nil, fmt.Errorf("cow: invalid cluster_bits %d in %s (qcow2 range 9..21)", cb, path)
	}
	if cm := binary.BigEndian.Uint32(hdrBuf[0x20:]); cm != 0 {
		f.Close()
		return nil, fmt.Errorf("cow: encrypted qcow2 (crypt_method=%d) unsupported in %s", cm, path)
	}
	if inc := binary.BigEndian.Uint64(hdrBuf[0x48:]); inc != 0 {
		f.Close()
		return nil, fmt.Errorf("cow: qcow2 incompatible features %#x in %s unsupported", inc, path)
	}
	q := &qcow2Image{
		f:           f,
		clusterBits: cb,
		clusterSize: uint64(1) << cb,
		clusterMask: (uint64(1) << cb) - 1,
	}
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

	// Convert in ~1 MiB chunks. Raw sources have no cluster geometry, so
	// they convert at exactly 1 MiB; qcow2 sources round the baseline UP to
	// a whole multiple of the source's cluster size — one ReadAt then
	// resolves whole clusters in bulk (4 KiB clusters: 256 per call instead
	// of 1) without paying a per-cluster syscall per MiB.
	chunk := uint64(1) << 20
	if q, ok := img.(*qcow2Image); ok {
		if r := chunk % q.clusterSize; r != 0 {
			chunk += q.clusterSize - r
		}
	}
	size := img.Size()
	buf := make([]byte, chunk)
	for off := uint64(0); off < size; off += chunk {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := uint64(len(buf))
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
