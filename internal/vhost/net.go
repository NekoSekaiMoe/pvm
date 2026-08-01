package vhost

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

type NetDevice struct {
	tapFile *os.File
}

// ifreq struct for TUNSETIFF
type ifreq struct {
	name  [16]byte
	flags uint16
	pad   [22]byte
}

const (
	IFF_TAP   = 0x0002
	IFF_NO_PI = 0x1000
	TUNSETIFF = 0x400454ca
)

func NewNetDevice(tapName string, bridgeName string) (*NetDevice, error) {
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	var ifr ifreq
	ifr.flags = IFF_TAP | IFF_NO_PI
	copy(ifr.name[:], tapName)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	f := os.NewFile(uintptr(fd), tapName)
	
	// Bring tap interface up and attach to bridge
	exec.Command("ip", "link", "set", tapName, "up").Run()
	if bridgeName != "" {
		exec.Command("ip", "link", "set", tapName, "master", bridgeName).Run()
	}

	return &NetDevice{tapFile: f}, nil
}

// StartTX handles Transmit from Guest to Host (Queue 1). It reuses the
// VirtQueue epoll kick loop so it can be stopped via vq.stopFd.
func (n *NetDevice) StartTX(vq *VirtQueue, mem *Memory) {
	vq.runProcessor(func() bool {
		n.processTXAvailable(mem, vq)
		return true
	}, "NetTX")
}

// processTXAvailable drains pending TX descriptors for one kick.
func (n *NetDevice) processTXAvailable(mem *Memory, vq *VirtQueue) {
	if vq.Num == 0 {
		return
	}
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
		written := n.processTXChain(mem, vq, headIdx)
		vq.completeRequest(mem, headIdx, written)
		vq.LastAvail++
	}
}

func (n *NetDevice) processTXChain(mem *Memory, vq *VirtQueue, headIdx uint16) uint32 {
	currIdx := headIdx
	var written uint32

	iter := uint32(0)
	for {
		if iter >= vq.Num {
			return written
		}
		iter++

		descBytes, err := mem.GuestToHost(vq.DescAddr+uint64(currIdx)*16, 16)
		if err != nil {
			return written
		}

		addr := binary.LittleEndian.Uint64(descBytes[0:8])
		length := binary.LittleEndian.Uint32(descBytes[8:12])
		flags := binary.LittleEndian.Uint16(descBytes[12:14])
		next := binary.LittleEndian.Uint16(descBytes[14:16])

		buf, err := mem.GuestToHost(addr, uint64(length))
		if err != nil {
			return written
		}

		if iter == 1 {
			// virtio-net header (10/12 bytes). Skip it for TAP write.
			hdrLen := uint32(10)
			if length > hdrLen {
				nw, err := n.tapFile.Write(buf[hdrLen:])
				if nw > 0 {
					written += uint32(nw)
				}
				if err != nil {
					return written
				}
			}
		} else {
			nw, err := n.tapFile.Write(buf)
			if nw > 0 {
				written += uint32(nw)
			}
			if err != nil {
				return written
			}
		}

		if (flags & VRingDescFNext) == 0 {
			break
		}
		currIdx = next
	}
	return written
}

// StartRX handles Receive from Host to Guest (Queue 0). It reads packets from
// the TAP and pushes them into available guest buffers. The loop terminates
// when the TAP read fails (closed) or when the queue's stopFd fires; the stop
// fd is checked between packets so shutdown does not stall on a blocking TAP
// read.
func (n *NetDevice) StartRX(vq *VirtQueue, mem *Memory) {
	packetBuf := make([]byte, 65536)
	for {
		// Bail out early if the server is shutting this queue down.
		if vq.isStopping() {
			return
		}
		// Read packet from TAP.
		plen, err := n.tapFile.Read(packetBuf)
		if err != nil {
			return
		}
		if plen <= 0 {
			continue
		}
		n.processRXAvailable(mem, vq, packetBuf[:plen])
	}
}

// processRXAvailable tries to place one packet into available guest buffers.
func (n *NetDevice) processRXAvailable(mem *Memory, vq *VirtQueue, packet []byte) {
	if vq.Num == 0 {
		return
	}
	availBytes, err := mem.GuestToHost(vq.AvailAddr, 4)
	if err != nil {
		return
	}
	availIdx := binary.LittleEndian.Uint16(availBytes[2:4])
	if vq.LastAvail == availIdx {
		// No descriptors available; drop the packet.
		return
	}
	ringOffset := uint64(4 + (int(vq.LastAvail)%int(vq.Num))*2)
	headBytes, err := mem.GuestToHost(vq.AvailAddr+ringOffset, 2)
	if err != nil {
		return
	}
	headIdx := binary.LittleEndian.Uint16(headBytes)
	written := n.processRXChain(mem, vq, headIdx, packet)
	vq.completeRequest(mem, headIdx, written)
	vq.LastAvail++
}

func (n *NetDevice) processRXChain(mem *Memory, vq *VirtQueue, headIdx uint16, packet []byte) uint32 {
	currIdx := headIdx
	var written uint32
	pktOffset := uint32(0)

	iter := uint32(0)
	for {
		if iter >= vq.Num {
			return written
		}
		iter++

		descBytes, err := mem.GuestToHost(vq.DescAddr+uint64(currIdx)*16, 16)
		if err != nil {
			return written
		}

		addr := binary.LittleEndian.Uint64(descBytes[0:8])
		length := binary.LittleEndian.Uint32(descBytes[8:12])
		flags := binary.LittleEndian.Uint16(descBytes[12:14])
		next := binary.LittleEndian.Uint16(descBytes[14:16])

		buf, err := mem.GuestToHost(addr, uint64(length))
		if err != nil {
			return written
		}

		if iter == 1 {
			// Write dummy 10-byte virtio-net header (all zeros)
			hdrLen := uint32(10)
			for i := uint32(0); i < hdrLen && i < length; i++ {
				buf[i] = 0
			}
			if length > hdrLen {
				chunk := length - hdrLen
				if uint32(len(packet))-pktOffset < chunk {
					chunk = uint32(len(packet)) - pktOffset
				}
				copy(buf[hdrLen:], packet[pktOffset:pktOffset+chunk])
				pktOffset += chunk
				written += hdrLen + chunk
			} else {
				written += hdrLen
			}
		} else {
			chunk := length
			if uint32(len(packet))-pktOffset < chunk {
				chunk = uint32(len(packet)) - pktOffset
			}
			copy(buf, packet[pktOffset:pktOffset+chunk])
			pktOffset += chunk
			written += chunk
		}

		if (flags & VRingDescFNext) == 0 || pktOffset >= uint32(len(packet)) {
			break
		}
		currIdx = next
	}
	return written
}
