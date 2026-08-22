package vu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

// virtio-blk request types / status codes / config (linux/virtio_blk.h).
const (
	blkTIn          = 0
	blkTOut         = 1
	blkTFlush       = 4
	blkTGetID       = 8
	blkTDiscard     = 11
	blkTWriteZeroes = 13
	blkTBarrier     = 0x80000000

	blkSOK     = 0
	blkSIOErr  = 1
	blkSUnsupp = 2
)

const (
	blkConfigSize = 60 // sizeof(struct virtio_blk_config)
	blkID         = "pvm-vublk"
)

// Backend is the storage behind the virtio-blk device (raw file or qcow2
// with a backing chain; see internal/cow).
type Backend interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	Size() int64 // virtual size in bytes
	Close() error
}

// BlkDev is a virtio-blk device bound to a Backend.
type BlkDev struct {
	be  Backend
	ro  bool
	cfg [blkConfigSize]byte
}

// NewBlkDev builds the device: fills the virtio_blk_config from the backend.
func NewBlkDev(be Backend, readOnly bool) (*BlkDev, error) {
	d := &BlkDev{be: be, ro: readOnly}
	le := binary.LittleEndian
	le.PutUint64(d.cfg[0:], uint64(be.Size())/512) // capacity (sectors)
	le.PutUint32(d.cfg[8:], 65536)                 // size_max
	le.PutUint32(d.cfg[12:], 126)                  // seg_max
	le.PutUint32(d.cfg[20:], 512)                  // blk_size
	le.PutUint16(d.cfg[26:], 1)                    // topology.min_io_size
	le.PutUint32(d.cfg[28:], 1)                    // topology.opt_io_size
	le.PutUint16(d.cfg[34:], 1)                    // num_queues
	return d, nil
}

// features advertises the minimal modern virtio-blk feature set.
func (d *BlkDev) features() uint64 {
	f := uint64(1)<<virtioBlkFSizeMax |
		uint64(1)<<virtioBlkFSegMax |
		uint64(1)<<virtioBlkFBlkSize |
		uint64(1)<<virtioBlkFFlush |
		uint64(1)<<vhostUserFProtocolFeatures |
		uint64(1)<<virtioFVersion1
	if d.ro {
		f |= 1 << virtioBlkFRo
	}
	return f
}

// config returns the device config bytes at [offset, offset+size).
func (d *BlkDev) config(offset, size uint32) ([]byte, error) {
	// 64-bit arithmetic: offset and size are peer-controlled and offset+size
	// must not wrap around uint32.
	if uint64(offset)+uint64(size) > blkConfigSize {
		return nil, fmt.Errorf("vu: config read out of range (off %d size %d)", offset, size)
	}
	out := make([]byte, size)
	copy(out, d.cfg[offset:offset+size])
	return out, nil
}

// Bounce buffers are needed because backends take contiguous []byte while
// requests arrive as scatter-gather lists. They used to be allocated per
// request; pool them in power-of-two size buckets (512B..64KiB, matching the
// advertised size_max=65536) instead. Sizes beyond the largest bucket fall
// back to a plain make.
const (
	bufPoolMinSize = 512
	bufPoolBuckets = 8 // 512 << 7 == 64KiB
)

var bufPools [bufPoolBuckets]sync.Pool

func bufBucket(size int) int {
	b := 0
	for c := bufPoolMinSize; c < size && b < bufPoolBuckets-1; c <<= 1 {
		b++
	}
	return b
}

// getBuf returns a buffer with at least n bytes. Sizes within the pooled
// range (512B..64KiB, the advertised size_max) are served from the
// power-of-two bucket pools; anything larger is a plain non-pooled
// allocation — putBuf's capacity check simply ignores it on return. The
// caller must return every buffer via putBuf when done; call sites never
// duplicate the range decision.
func getBuf(n int) []byte {
	if n > bufPoolMinSize<<(bufPoolBuckets-1) {
		return make([]byte, n) // oversized: not poolable
	}
	b := bufBucket(n)
	if v := bufPools[b].Get(); v != nil {
		return v.([]byte)[:n]
	}
	return make([]byte, n, bufPoolMinSize<<b)
}

func putBuf(buf []byte) {
	b := bufBucket(cap(buf))
	if b < 0 || b >= bufPoolBuckets || cap(buf) != bufPoolMinSize<<b {
		return // not a pooled bucket size
	}
	bufPools[b].Put(buf[:cap(buf)])
}

type outhdr struct {
	typ    uint32
	ioprio uint32
	sector uint64
}

// inRange validates a guest-controlled sector request against the backend
// size with overflow-safe arithmetic: sector*512 must not wrap int64/uint64
// and sector*512+length must stay within the declared virtual size.
func (d *BlkDev) inRange(sector uint64, length int) bool {
	if sector > math.MaxUint64/512 || length < 0 {
		return false
	}
	off := sector * 512
	if uint64(length) > math.MaxUint64-off {
		return false
	}
	return off+uint64(length) <= uint64(d.be.Size())
}

// process executes one request element against the backend.
func (d *BlkDev) process(e *elem) (usedLen uint32, err error) {
	if len(e.outSG) < 1 || len(e.inSG) < 1 {
		return 0, errors.New("vu: blk request missing headers")
	}
	out := e.outSG[0]
	if len(out) < 16 {
		return 0, errors.New("vu: blk outhdr too small")
	}
	h := outhdr{
		typ:    binary.LittleEndian.Uint32(out[0:]),
		ioprio: binary.LittleEndian.Uint32(out[4:]),
		sector: binary.LittleEndian.Uint64(out[8:]),
	}
	// Last in-buffer is the status byte; the rest is data payload.
	inSG := e.inSG
	statusBuf := inSG[len(inSG)-1]
	if len(statusBuf) < 1 {
		return 0, errors.New("vu: blk inhdr too small")
	}
	dataIn := inSG[:len(inSG)-1]
	dataOut := e.outSG[1:]
	status := byte(blkSOK)

	switch h.typ &^ blkTBarrier {
	case blkTIn:
		n := sgLen(dataIn)
		if !d.inRange(h.sector, n) {
			status = blkSIOErr
			usedLen = 1
			break
		}
		// Bounce buffer: pooled for common sizes, plain allocation for
		// oversized (guest-coalesced) reads — getBuf owns that decision.
		buf := getBuf(n)
		m, rerr := d.be.ReadAt(buf, int64(h.sector)*512)
		if rerr != nil && rerr != io.EOF {
			status = blkSIOErr
		} else {
			// io.EOF is a partial success: deliver the bytes actually read.
			sgCopy(dataIn, buf[:m])
		}
		usedLen = uint32(m) + 1
		putBuf(buf)
	case blkTOut:
		n := sgLen(dataOut)
		if d.ro || !d.inRange(h.sector, n) {
			status = blkSIOErr
			usedLen = 1
			break
		}
		// Gather into a bounce buffer: pooled when possible, plain otherwise
		// (getBuf owns the range decision).
		buf := getBuf(n)
		sgGatherInto(dataOut, buf)
		if _, err := d.be.WriteAt(buf, int64(h.sector)*512); err != nil {
			status = blkSIOErr
		}
		usedLen = 1
		putBuf(buf)
	case blkTFlush:
		if err := d.be.Sync(); err != nil {
			status = blkSIOErr
		}
		usedLen = 1
	case blkTGetID:
		n := sgLen(dataIn)
		if n > 20 {
			n = 20
		}
		id := []byte(blkID)
		if len(id) > n {
			id = id[:n]
		}
		sgCopy(dataIn, id)
		status = blkSOK
		usedLen = uint32(n) + 1
	default:
		status = blkSUnsupp
		usedLen = 1
	}
	statusBuf[0] = status
	return usedLen, nil
}

func sgLen(sg [][]byte) int {
	n := 0
	for _, b := range sg {
		n += len(b)
	}
	return n
}

func sgGather(sg [][]byte) []byte {
	out := make([]byte, 0, sgLen(sg))
	for _, b := range sg {
		out = append(out, b...)
	}
	return out
}

// sgGatherInto copies the concatenated scatter-gather list into dst, which
// must be at least sgLen(sg) bytes.
func sgGatherInto(sg [][]byte, dst []byte) {
	off := 0
	for _, b := range sg {
		off += copy(dst[off:], b)
	}
}

// sgCopy copies data into the front of the scatter-gather list. It must NOT
// reslice sg[0]-style: sg's backing array of slice headers is shared with
// the caller's elem.inSG/outSG, and writing a resliced header into slot 0
// would corrupt the caller's view (the array write then appears to vanish).
// Iterate with an index instead.
func sgCopy(sg [][]byte, data []byte) {
	i, off := 0, 0
	for len(data) > 0 && i < len(sg) {
		n := copy(sg[i][off:], data)
		data = data[n:]
		off += n
		if off == len(sg[i]) {
			i++
			off = 0
		}
	}
}
