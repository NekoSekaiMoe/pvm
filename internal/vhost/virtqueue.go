package vhost

import (
	"encoding/binary"
	"fmt"
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
}

const (
	VRingDescSize = 16
	VRingDescFNext = 1
	VRingDescFWrite = 2
)

// ProcessRing waits for a kick and processes pending descriptors
func (vq *VirtQueue) ProcessRing(mem *Memory, blk *BlockDevice) {
	buf := make([]byte, 8) // eventfd counter is 8 bytes
	for {
		n, err := syscall.Read(vq.KickFd, buf)
		if err != nil || n != 8 {
			fmt.Printf("[VirtQueue %d] Kick FD closed or error: %v\n", vq.Index, err)
			break
		}

		// Look up avail ring index
		// avail ring header: flags (2 bytes), idx (2 bytes), ring (num * 2 bytes), used_event (2 bytes)
		availBytes, err := mem.GuestToHost(vq.AvailAddr, 4)
		if err != nil {
			continue
		}
		
		availIdx := binary.LittleEndian.Uint16(availBytes[2:4])
		
		// Process all pending descriptors
		for vq.LastAvail != availIdx {
			// Find the descriptor head index in the avail ring
			ringOffset := uint64(4 + (vq.LastAvail % uint16(vq.Num)) * 2)
			headBytes, err := mem.GuestToHost(vq.AvailAddr + ringOffset, 2)
			if err != nil {
				break
			}
			headIdx := binary.LittleEndian.Uint16(headBytes)
			
			// Process descriptor chain starting at headIdx
			vq.processDescChain(mem, headIdx, blk)

			vq.LastAvail++
		}
	}
}

func (vq *VirtQueue) processDescChain(mem *Memory, headIdx uint16, blk *BlockDevice) {
	currIdx := headIdx
	var reqType uint32
	var sector uint64
	var written uint32

	// We expect 3 parts: outhdr, data, status.
	// We'll collect data slices if there are multiple.
	var dataSlices [][]byte
	var statusSlice []byte
	
	isFirst := true
	for {
		descBytes, err := mem.GuestToHost(vq.DescAddr+uint64(currIdx)*16, 16)
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
			// outhdr
			if length == 16 {
				reqType = binary.LittleEndian.Uint32(buf[0:4])
				sector = binary.LittleEndian.Uint64(buf[8:16])
			}
			isFirst = false
		} else {
			if (flags & VRingDescFNext) == 0 {
				// Last descriptor is the status byte (1 byte)
				statusSlice = buf
			} else {
				// Intermediate descriptors are data
				dataSlices = append(dataSlices, buf)
			}
		}

		if (flags & VRingDescFNext) == 0 {
			break
		}
		currIdx = next
	}

	status := byte(VirtioBlkSUnsupp)
	offset := int64(sector) * 512

	if blk != nil {
		switch reqType {
		case VirtioBlkTIn:
			// Read from disk to guest memory
			go func() {
				ch := make(chan iouring.Result, 1)
				blk.IOUR().SubmitRequest(iouring.Preadv(blk.Fd(), dataSlices, uint64(offset)), ch)
				res := <-ch
				var st byte = VirtioBlkSOk
				if res.Err() != nil {
					st = VirtioBlkSIoErr
				}
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = st
				}
				
				// +1 for the status byte
				ret, _ := res.ReturnInt()
				if ret < 0 { ret = 0 }
				vq.completeRequest(mem, headIdx, uint32(ret)+1)
			}()
			return // return immediately, completion is handled async

		case VirtioBlkTOut:
			// Write from guest memory to disk
			go func() {
				ch := make(chan iouring.Result, 1)
				blk.IOUR().SubmitRequest(iouring.Pwritev(blk.Fd(), dataSlices, offset), ch)
				res := <-ch
				var st byte = VirtioBlkSOk
				if res.Err() != nil {
					st = VirtioBlkSIoErr
				}
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = st
				}
				
				// +1 for the status byte
				ret, _ := res.ReturnInt()
				if ret < 0 { ret = 0 }
				vq.completeRequest(mem, headIdx, uint32(ret)+1)
			}()
			return // return immediately, completion is handled async

		case VirtioBlkTFlush:
			go func() {
				ch := make(chan iouring.Result, 1)
				blk.IOUR().SubmitRequest(iouring.Fsync(blk.Fd()), ch)
				<-ch
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = VirtioBlkSOk
				}
				vq.completeRequest(mem, headIdx, 1)
			}()
			return
		}
	}

	if statusSlice != nil && len(statusSlice) >= 1 {
		statusSlice[0] = status
		written++ // status byte counts as written
	}
	
	vq.completeRequest(mem, headIdx, written)
}

func (vq *VirtQueue) completeRequest(mem *Memory, headIdx uint16, written uint32) {
	// Write back to Used ring to acknowledge completion
	// used ring header: flags (2 bytes), idx (2 bytes), ring (num * 8 bytes), avail_event (2 bytes)
	usedIdxBytes, err := mem.GuestToHost(vq.UsedAddr+2, 2)
	if err == nil {
		usedIdx := binary.LittleEndian.Uint16(usedIdxBytes)
		
		// elem is 8 bytes: id (4 bytes), len (4 bytes)
		elemOffset := uint64(4 + (usedIdx % uint16(vq.Num)) * 8)
		elemBytes, err := mem.GuestToHost(vq.UsedAddr + elemOffset, 8)
		if err == nil {
			binary.LittleEndian.PutUint32(elemBytes[0:4], uint32(headIdx))
			binary.LittleEndian.PutUint32(elemBytes[4:8], written)
			
			// increment usedIdx
			binary.LittleEndian.PutUint16(usedIdxBytes, usedIdx+1)
			
			// Notify guest by writing to CallFd
			if vq.CallFd > 0 {
				event := []byte{1, 0, 0, 0, 0, 0, 0, 0}
				syscall.Write(vq.CallFd, event)
			}
		}
	}
}
