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
	"os"
	"sync"
)

// WritableBackend is the storage interface the vhost-user-blk device needs.
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
	// Reopen RW (openGuestImage opened O_RDONLY).
	q.f.Close()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if q.backing != nil {
			q.backing.Close()
		}
		return nil, err
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

// WriteAt writes at a guest offset, allocating clusters on first write and
// copying backing content for partial-cluster writes (qcow2 CoW).
func (w *qcow2Writable) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := 0
	for total < len(p) {
		guest := uint64(off) + uint64(total)
		if guest >= w.hdr.size {
			return total, fmt.Errorf("cow: write beyond virtual size (%#x >= %#x)", guest, w.hdr.size)
		}
		clusterIdx := guest >> clusterBits
		inCluster := guest & w.clusterMask
		n := uint64(clusterSize) - inCluster
		if rem := uint64(len(p)) - uint64(total); rem < n {
			n = rem
		}
		host, err := w.hostOffset(clusterIdx)
		if err != nil {
			return total, err
		}
		if host == 0 {
			// Unallocated (or zero) cluster: allocate + COW.
			fullCluster := inCluster == 0 && n == clusterSize
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
	l1Idx := clusterIdx / (clusterSize / 8)
	l2Idx := clusterIdx % (clusterSize / 8)
	if l1Idx >= uint64(w.hdr.l1Size) {
		return 0, fmt.Errorf("cow: guest cluster %d beyond L1", clusterIdx)
	}
	var l1e uint64
	if err := w.readUint64At(&l1e, w.hdr.l1Offset+l1Idx*8); err != nil {
		return 0, err
	}
	l2Off := l1e & l1eOffsetMask
	if l2Off == 0 {
		return 0, nil
	}
	var l2e uint64
	if err := w.readUint64At(&l2e, l2Off+l2Idx*8); err != nil {
		return 0, err
	}
	if l2e&oflagCompressed != 0 {
		return 0, fmt.Errorf("cow: compressed clusters unsupported")
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
		// the partial write.
		buf := make([]byte, clusterSize)
		clusterStart := int64(clusterIdx << clusterBits)
		if _, err := w.qcow2Image.ReadAt(buf, clusterStart); err != nil {
			return 0, fmt.Errorf("cow: read backing for CoW at %#x: %w", clusterStart, err)
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

// linkL2 points the L2 entry for clusterIdx at hostOff, allocating the L2
// table first if needed.
func (w *qcow2Writable) linkL2(clusterIdx, hostOff uint64) error {
	l1Idx := clusterIdx / (clusterSize / 8)
	l2Idx := clusterIdx % (clusterSize / 8)
	var l1e uint64
	if err := w.readUint64At(&l1e, w.hdr.l1Offset+l1Idx*8); err != nil {
		return err
	}
	l2Off := l1e & l1eOffsetMask
	if l2Off == 0 {
		var err error
		l2Off, err = w.allocCluster()
		if err != nil {
			return err
		}
		// Fresh L2 table: zero it, refcount 1, link L1.
		if _, err := w.f.WriteAt(make([]byte, clusterSize), int64(l2Off)); err != nil {
			return err
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], l2Off|oflagCopied)
		if _, err := w.f.WriteAt(b[:], int64(w.hdr.l1Offset+l1Idx*8)); err != nil {
			return err
		}
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], hostOff|oflagCopied)
	if _, err := w.f.WriteAt(b[:], int64(l2Off+l2Idx*8)); err != nil {
		return err
	}
	return nil
}

// allocCluster appends a zeroed cluster at EOF and sets its refcount to 1.
// Returns the host offset.
func (w *qcow2Writable) allocCluster() (uint64, error) {
	off := w.fileSize
	if off%clusterSize != 0 {
		return 0, fmt.Errorf("cow: host file size %#x not cluster-aligned", off)
	}
	if _, err := w.f.WriteAt(make([]byte, clusterSize), int64(off)); err != nil {
		return 0, err
	}
	w.fileSize += clusterSize
	if err := w.bumpRefcount(off >> clusterBits); err != nil {
		return 0, err
	}
	return off, nil
}

// bumpRefcount sets refcount(clusterIdx) = 1, allocating additional refcount
// blocks (registered in the refcount table) when the image grows past what
// the existing blocks cover. The refcount table itself is fixed at one
// cluster (8192 entries → covers 16 TiB of host file), sized at create time.
func (w *qcow2Writable) bumpRefcount(clusterIdx uint64) error {
	const entriesPerBlock = clusterSize / 2 // 32768 u16 entries
	blockIdx := clusterIdx / entriesPerBlock
	inBlock := clusterIdx % entriesPerBlock
	maxBlocks := uint64(w.hdr.refcountClusters) * (clusterSize / 8)
	if blockIdx >= maxBlocks {
		return fmt.Errorf("cow: refcount table full at cluster %d", clusterIdx)
	}
	var tableEntry uint64
	if err := w.readUint64At(&tableEntry, w.hdr.refcountOffset+blockIdx*8); err != nil {
		return err
	}
	blockOff := tableEntry & 0xfffffffffffffe00 // REFT_OFFSET_MASK
	if blockOff == 0 {
		// Allocate a new refcount block at EOF and register it in the table.
		blockOff = w.fileSize
		if _, err := w.f.WriteAt(make([]byte, clusterSize), int64(blockOff)); err != nil {
			return err
		}
		w.fileSize += clusterSize
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], blockOff)
		if _, err := w.f.WriteAt(b[:], int64(w.hdr.refcountOffset+blockIdx*8)); err != nil {
			return err
		}
		// The new block's own cluster also needs refcount 1; now that the
		// table entry is registered, recursion lands in the right block
		// (its own if covered, an earlier one otherwise).
		selfCluster := blockOff >> clusterBits
		if selfCluster != clusterIdx {
			if err := w.bumpRefcount(selfCluster); err != nil {
				return err
			}
		}
	}
	var c [2]byte
	binary.BigEndian.PutUint16(c[:], 1)
	if _, err := w.f.WriteAt(c[:], int64(blockOff+inBlock*2)); err != nil {
		return err
	}
	return nil
}
