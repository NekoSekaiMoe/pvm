package vhost

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"

	"github.com/iceber/iouring-go"
)

type VirtQueue struct {
	Index     uint32
	Num       uint32
	LastAvail uint16
	DescAddr  uint64
	AvailAddr uint64
	UsedAddr  uint64
	KickFd    int
	CallFd    int

	// usedMu serializes writes to the used ring (completeRequest). virtio-blk
	// completes requests from multiple goroutines (one per io_uring request),
	// so the read-modify-write of the used index must be guarded or the guest
	// observes corrupt/out-of-order completions.
	usedMu sync.Mutex
}

const (
	VRingDescSize   = 16
	VRingDescFNext  = 1
	VRingDescFWrite = 2
)

// virtio-blk request out-header (16 bytes, little-endian):
//   u32 type; u32 reserved; u64 sector
const virtioBlkOutHdrLen = 16

// ProcessRing waits for a kick and processes pending descriptors.
//
// A read error on the kick fd is not always fatal: EAGAIN/EINTR can happen
// spuriously. Only when the fd is actually closed (EOF / EBADF) do we stop the
// processor.
func (vq *VirtQueue) ProcessRing(mem *Memory, blk *BlockDevice) {
	buf := make([]byte, 8) // eventfd counter is 8 bytes
	for {
		n, err := syscall.Read(vq.KickFd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			// fd closed (EOF, EBADF, etc.) — permanent, stop the processor.
			fmt.Printf("[VirtQueue %d] Kick FD closed: %v\n", vq.Index, err)
			return
		}
		if n != 8 {
			continue
		}

		vq.processAvailable(mem, blk)
	}
}

// processAvailable drains all descriptors the guest has posted since the last
// scan. Reading the avail index once per kick is sufficient; if new buffers
// are posted concurrently the next kick will pick them up.
func (vq *VirtQueue) processAvailable(mem *Memory, blk *BlockDevice) {
	availBytes, err := mem.GuestToHost(vq.AvailAddr, 4)
	if err != nil {
		return
	}
	availIdx := binary.LittleEndian.Uint16(availBytes[2:4])

	for vq.LastAvail != availIdx {
		ringOffset := uint64(4 + (int(vq.LastAvail)%int(vq.Num))*2)
		headBytes, err := mem.GuestToHost(vq.AvailAddr+ringOffset, 2)
		if err != nil {
			return
		}
		headIdx := binary.LittleEndian.Uint16(headBytes)

		vq.processDescChain(mem, headIdx, blk)
		vq.LastAvail++
	}
}

func (vq *VirtQueue) processDescChain(mem *Memory, headIdx uint16, blk *BlockDevice) {
	currIdx := headIdx
	var reqType uint32
	var sector uint64
	var written uint32

	var dataSlices [][]byte
	var statusSlice []byte

	isFirst := true
	iter := uint32(0)
	for {
		if iter >= vq.Num {
			// descriptor chain longer than the ring — malformed, fail it.
			if statusSlice != nil && len(statusSlice) >= 1 {
				statusSlice[0] = VirtioBlkSIoErr
			}
			vq.completeRequest(mem, headIdx, 1)
			return
		}
		iter++

		descBytes, err := mem.GuestToHost(vq.DescAddr+uint64(currIdx)*VRingDescSize, VRingDescSize)
		if err != nil {
			fmt.Printf("[VirtQueue %d] failed to map desc %d\n", vq.Index, currIdx)
			return
		}

		addr := binary.LittleEndian.Uint64(descBytes[0:8])
		length := binary.LittleEndian.Uint32(descBytes[8:12])
		flags := binary.LittleEndian.Uint16(descBytes[12:14])
		next := binary.LittleEndian.Uint16(descBytes[14:16])

		buf, err := mem.GuestToHost(addr, uint64(length))
		if err != nil {
			fmt.Printf("[VirtQueue %d] failed to map desc buf at 0x%x\n", vq.Index, addr)
			return
		}

		if isFirst {
			// virtio-blk out-header: u32 type, u32 reserved, u64 sector.
			if length >= virtioBlkOutHdrLen {
				reqType = binary.LittleEndian.Uint32(buf[0:4])
				sector = binary.LittleEndian.Uint64(buf[8:16])
			}
			isFirst = false
		} else {
			if (flags & VRingDescFNext) == 0 {
				// Last descriptor is the status byte (1 byte).
				statusSlice = buf
			} else {
				// Intermediate descriptors are data.
				dataSlices = append(dataSlices, buf)
			}
		}

		if (flags & VRingDescFNext) == 0 {
			break
		}
		currIdx = next
	}

	offset := int64(sector) * 512

	if blk != nil {
		switch reqType {
		case VirtioBlkTIn:
			// Read from disk into guest memory.
			go func() {
				ch := make(chan iouring.Result, 1)
				_, err := blk.IOUR().SubmitRequest(iouring.Preadv(blk.Fd(), dataSlices, uint64(offset)), ch)
				if err != nil {
					if statusSlice != nil && len(statusSlice) >= 1 {
						statusSlice[0] = VirtioBlkSIoErr
					}
					vq.completeRequest(mem, headIdx, 1)
					return
				}
				res := <-ch
				st := byte(VirtioBlkSOk)
				if res.Err() != nil {
					st = VirtioBlkSIoErr
				}
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = st
				}
				ret, _ := res.ReturnInt()
				if ret < 0 {
					ret = 0
				}
				// +1 for the status byte.
				vq.completeRequest(mem, headIdx, uint32(ret)+1)
			}()
			return

		case VirtioBlkTOut:
			// Write from guest memory to disk.
			go func() {
				ch := make(chan iouring.Result, 1)
				_, err := blk.IOUR().SubmitRequest(iouring.Pwritev(blk.Fd(), dataSlices, uint64(offset)), ch)
				if err != nil {
					if statusSlice != nil && len(statusSlice) >= 1 {
						statusSlice[0] = VirtioBlkSIoErr
					}
					vq.completeRequest(mem, headIdx, 1)
					return
				}
				res := <-ch
				st := byte(VirtioBlkSOk)
				if res.Err() != nil {
					st = VirtioBlkSIoErr
				}
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = st
				}
				ret, _ := res.ReturnInt()
				if ret < 0 {
					ret = 0
				}
				vq.completeRequest(mem, headIdx, uint32(ret)+1)
			}()
			return

		case VirtioBlkTFlush:
			go func() {
				ch := make(chan iouring.Result, 1)
				_, err := blk.IOUR().SubmitRequest(iouring.Fsync(blk.Fd()), ch)
				if err != nil {
					if statusSlice != nil && len(statusSlice) >= 1 {
						statusSlice[0] = VirtioBlkSIoErr
					}
					vq.completeRequest(mem, headIdx, 1)
					return
				}
				<-ch
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = VirtioBlkSOk
				}
				vq.completeRequest(mem, headIdx, 1)
			}()
			return
		}
	}

	// Unsupported request type.
	if statusSlice != nil && len(statusSlice) >= 1 {
		statusSlice[0] = VirtioBlkSUnsupp
		written++ // status byte counts as written
	}
	vq.completeRequest(mem, headIdx, written)
}

// completeRequest appends a used element and notifies the guest. Concurrent
// callers (one per in-flight io_uring request) are serialized via usedMu so
// the used index stays consistent.
func (vq *VirtQueue) completeRequest(mem *Memory, headIdx uint16, written uint32) {
	vq.usedMu.Lock()
	defer vq.usedMu.Unlock()

	// used ring header: flags(2), idx(2), ring(num*8), avail_event(2)
	usedIdxBytes, err := mem.GuestToHost(vq.UsedAddr+2, 2)
	if err != nil {
		return
	}
	usedIdx := binary.LittleEndian.Uint16(usedIdxBytes)

	// elem is 8 bytes: id(4), len(4)
	elemOffset := uint64(4 + (int(usedIdx)%int(vq.Num))*8)
	elemBytes, err := mem.GuestToHost(vq.UsedAddr+elemOffset, 8)
	if err != nil {
		return
	}
	binary.LittleEndian.PutUint32(elemBytes[0:4], uint32(headIdx))
	binary.LittleEndian.PutUint32(elemBytes[4:8], written)

	// Make sure the elem is visible before bumping the index.
	binary.LittleEndian.PutUint16(usedIdxBytes, usedIdx+1)

	// Notify the guest by writing to CallFd (eventfd counter = 1).
	if vq.CallFd > 0 {
		event := []byte{1, 0, 0, 0, 0, 0, 0, 0}
		syscall.Write(vq.CallFd, event)
	}
}
