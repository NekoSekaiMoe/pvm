package vhost

import (
	"encoding/binary"
	"fmt"
	"syscall"
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
func (vq *VirtQueue) ProcessRing(mem *Memory) {
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
			vq.processDescChain(mem, headIdx)

			vq.LastAvail++
		}
	}
}

func (vq *VirtQueue) processDescChain(mem *Memory, headIdx uint16) {
	// Dummy processing. Will implement virtio-blk logic here later.
	fmt.Printf("[VirtQueue %d] Processing chain head: %d\n", vq.Index, headIdx)
	
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
			binary.LittleEndian.PutUint32(elemBytes[4:8], 0) // written len
			
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
