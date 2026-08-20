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
	qcow2V3HeaderLen = 104 // minimum v3 header_length per the qcow2 spec
	clusterBits      = 12  // 4 KiB clusters (default): matches ext4 block size
	clusterSize      = 1 << clusterBits
	refcountOrder    = 4 // 2^4 = 16-bit refcount entries (qemu-img default)
	extBackingFormat = 0xE2792ACA

	// maxBackingNameLen is the qcow2 spec cap on the backing file name
	// (1023 bytes; qemu-img enforces the same bound on create and open).
	maxBackingNameLen = 1023

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
	l1Offset         uint64
	l1Size           uint32
	refcountOffset   uint64
	refcountClusters uint32
	// snapshots/snapshotsOffset are parsed for a guard: Compact refuses
	// images with internal snapshots (the L1 active-table walk would skip
	// snapshot-only clusters, silently dropping them).
	snapshots       uint32
	snapshotsOffset uint64
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
		if len(backingPath) > maxBackingNameLen || off+uint64(len(backingPath)) > cs {
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
	// up to l1Off, the L1 table, then the preallocated L2 tables. The zero
	// regions (unused refcount-block remainder and preallocated L2 tables)
	// are extended SPARSELY via Truncate rather than written: a 1 TiB image
	// at 4 KiB clusters has 512K L2 tables = 2 GiB that must read as zeros
	// but should never consume disk (qemu-img create produces sparse images
	// too). Truncate extends the file with a sparse hole, so st_blocks stays
	// tiny while reads return zeros.
	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("cow: write qcow2 metadata: %w", err)
	}
	if err := f.Truncate(int64(lay.l1Off)); err != nil {
		return fmt.Errorf("cow: zero-fill refcount blocks: %w", err)
	}
	if _, err := f.Seek(int64(lay.l1Off), io.SeekStart); err != nil {
		return fmt.Errorf("cow: seek to L1: %w", err)
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
	// Preallocated L2 tables are all zeros; extend the file sparsely over
	// them rather than streaming zeros (see the Truncate note above).
	if lay.l2Count > 0 {
		if err := f.Truncate(int64(lay.l2Off + lay.l2Count*cs)); err != nil {
			return fmt.Errorf("cow: extend preallocated L2 tables: %w", err)
		}
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
	// Format reports the on-disk format the image was opened as: "qcow2"
	// or "raw". It is the ground truth openGuestImage probed from the
	// magic, used to cross-check a header-DECLARED backing format against
	// what the backing file actually is.
	Format() string
	Close() error
}

type rawImage struct {
	f    *os.File
	size uint64
}

func (r *rawImage) ReadAt(p []byte, off int64) (int, error) { return r.f.ReadAt(p, off) }
func (r *rawImage) Size() uint64                            { return r.size }
func (r *rawImage) Format() string                          { return "raw" }
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
	// backingAbs is the backing file path resolved to ABSOLUTE at open time
	// (qcow2 resolves a relative backing name against the image's own
	// directory). Empty when the image is standalone. Compact uses it to
	// rebuild an overlay that references the same backing.
	backingAbs string
	// backingName is the backing file name EXACTLY as stored in the header
	// (qcow2 resolves it relative to the image's own directory when not
	// absolute). Compact re-emits it verbatim into the rebuilt overlay so a
	// relocated overlay+backing pair keeps resolving; backingAbs above is
	// the resolved absolute copy used for actually opening the file.
	backingName string
	// backingFormat is the backing format parsed from the qcow2 header
	// extension (extBackingFormat), if present. "" means the header did not
	// carry one, so callers must probe (isQcow2) themselves. Compact passes
	// this through to createQcow2 so a qcow2 backing is never accidentally
	// defaulted to raw.
	backingFormat string
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
func (q *qcow2Image) Format() string { return "qcow2" }

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
		snapshots:        binary.BigEndian.Uint32(hdrBuf[0x3C:]),
		snapshotsOffset:  binary.BigEndian.Uint64(hdrBuf[0x40:]),
	}
	// v3 header_length (offset 0x64) is where header extensions START —
	// not necessarily our own qcow2HeaderLen. The spec minimum is 104 (the
	// bare fixed v3 header); foreign writers (qemu-img included) may emit
	// 104, so a fixed 112 start would skip the first 8 bytes of an extension
	// and misparse its tail as a new extension header. Reject impossible
	// values: below the fixed header, or beyond cluster 0 where extensions
	// must live.
	hdrLen := uint64(binary.BigEndian.Uint32(hdrBuf[0x64:]))
	if hdrLen < qcow2V3HeaderLen {
		f.Close()
		return nil, fmt.Errorf("cow: invalid header_length %d in %s (minimum %d)", hdrLen, path, qcow2V3HeaderLen)
	}
	if hdrLen > q.clusterSize {
		f.Close()
		return nil, fmt.Errorf("cow: invalid header_length %d in %s (exceeds cluster size %d)", hdrLen, path, q.clusterSize)
	}
	// The spec requires header_length to be a multiple of 8 (like every
	// extension-boundary offset); qemu-img rejects unaligned values because
	// extension walking would go off-grid.
	if hdrLen%8 != 0 {
		f.Close()
		return nil, fmt.Errorf("cow: invalid header_length %d in %s (not 8-byte aligned)", hdrLen, path)
	}
	bfOff := binary.BigEndian.Uint64(hdrBuf[0x08:])
	bfSize := binary.BigEndian.Uint32(hdrBuf[0x10:])
	// Header extensions live between the fixed header and the backing-file
	// name (bfOff). Parse them to recover the stored backing format
	// (extBackingFormat) instead of re-probing later — a probe can race or
	// disagree with what qemu-img wrote, and Compact must rebuild with the
	// SAME format the source declared.
	extEnd := bfOff
	if extEnd == 0 {
		// No backing name: extensions still end with the 0-marker. Bound
		// the parse at the fixed header length, or header_length if larger.
		extEnd = uint64(qcow2HeaderLen)
		if hdrLen > extEnd {
			extEnd = hdrLen
		}
	}
	// Extensions live in cluster 0 AFTER the fixed header, so hdrBuf
	// (only qcow2HeaderLen bytes) does not cover them. Read the whole
	// region once, if it actually contains extensions.
	var extBuf []byte
	if extEnd > uint64(qcow2HeaderLen) {
		if extEnd > q.clusterSize {
			f.Close()
			return nil, fmt.Errorf("cow: invalid header extension region in %s (end=%#x)", path, extEnd)
		}
		extBuf = make([]byte, extEnd)
		if _, err := f.ReadAt(extBuf, 0); err != nil && err != io.EOF {
			f.Close()
			return nil, fmt.Errorf("cow: read header extensions of %s: %w", path, err)
		}
	} else if extEnd < hdrLen {
		// A backing name that starts before header_length leaves no room
		// for the extensions the header claims exist.
		f.Close()
		return nil, fmt.Errorf("cow: invalid header extension region in %s (end=%#x before header_length=%#x)", path, extEnd, hdrLen)
	}
	e := hdrLen
	for e+8 <= extEnd {
		var magic, elen uint32
		if e+8 <= uint64(len(hdrBuf)) {
			magic = binary.BigEndian.Uint32(hdrBuf[e:])
			elen = binary.BigEndian.Uint32(hdrBuf[e+4:])
		} else {
			magic = binary.BigEndian.Uint32(extBuf[e:])
			elen = binary.BigEndian.Uint32(extBuf[e+4:])
		}
		if magic == 0 { // end-of-extensions marker
			break
		}
		dataOff := e + 8
		if uint64(elen) > extEnd-dataOff {
			f.Close()
			return nil, fmt.Errorf("cow: header extension %#x overflows header in %s", magic, path)
		}
		if magic == extBackingFormat && elen > 0 {
			name := string(extBuf[dataOff : dataOff+uint64(elen)])
			// Only the two formats this package can actually open are
			// acceptable. Anything else (vmdk, vpc, ...) would be unopenable
			// later and would be re-emitted verbatim by Compact into rebuilt
			// headers — reject at parse time with the offending value.
			if name != "raw" && name != "qcow2" {
				f.Close()
				return nil, fmt.Errorf("cow: unsupported backing format %q declared in %s (want raw or qcow2)", name, path)
			}
			q.backingFormat = name
		}
		e = dataOff + roundUp8(uint64(elen))
	}
	if bfSize > 0 {
		// The qcow2 spec caps the backing name at 1023 bytes (it must fit
		// in cluster 0 after the header); qemu-img enforces the same bound.
		if bfSize > maxBackingNameLen {
			f.Close()
			return nil, fmt.Errorf("cow: implausible backing name length %d in %s (max %d)", bfSize, path, maxBackingNameLen)
		}
		name := make([]byte, bfSize)
		if _, err := f.ReadAt(name, int64(bfOff)); err != nil {
			f.Close()
			return nil, fmt.Errorf("cow: read backing name in %s: %w", path, err)
		}
		backingPath := string(name)
		// Preserve the original name (pre-Abs) for Compact to re-emit
		// verbatim in rebuilt overlays — a relative name stays relative, so
		// the overlay+backing pair stays relocatable. A separate absolute
		// copy drives the actual open below.
		q.backingName = backingPath
		absBacking, err := filepath.Abs(filepath.Join(filepath.Dir(path), backingPath))
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("cow: resolve backing path of %s: %w", path, err)
		}
		if !filepath.IsAbs(backingPath) {
			backingPath = absBacking
		}
		backing, err := openGuestImage(backingPath)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("cow: open backing of %s: %w", path, err)
		}
		// If the header DECLARED a backing format, the opened file must
		// actually be that format. A mismatch (e.g. "raw" declared over a
		// qcow2 file) means the header lies; trusting it would poison every
		// rebuilt descendant that re-emits the declaration. Only probe
		// (no declaration) keeps the auto-detect behavior.
		if q.backingFormat != "" && backing.Format() != q.backingFormat {
			backing.Close()
			f.Close()
			return nil, fmt.Errorf("cow: backing format mismatch in %s: header declares %q but %s is %q",
				path, q.backingFormat, backingPath, backing.Format())
		}
		q.backing = backing
		q.backingAbs = backingPath // absolute; see filepath.Abs above
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
	// Dest must not be the source itself nor any member of its backing
	// chain: O_TRUNC below would destroy that data mid-read.
	if err := checkNotInChain(img, srcPath, destPath); err != nil {
		return err
	}

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
