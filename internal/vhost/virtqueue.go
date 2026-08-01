package vhost

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/iceber/iouring-go"
	"golang.org/x/sys/unix"
)

// noFd is the "not configured" sentinel for KickFd/CallFd. Real fds are always
// >= 0, so -1 cleanly means unset and lets the notification guard (CallFd >= 0)
// behave correctly (the prior zero value would have suppressed notification if
// fd 0 were ever handed out).
const noFd = -1

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

	// stopFd is an eventfd that wakes a ring processor blocked in epoll_wait
	// alongside KickFd, so Server can stop the processor promptly. We cannot
	// rely on closing KickFd to wake a blocked read on it: on Linux, closing
	// an fd that another goroutine is blocked in read() on does NOT wake that
	// read (verified empirically). Owned by Server; -1 until the processor is
	// started.
	stopFd int

	// stopping is set by Server.stopProcessor to signal RX/TX loops that poll
	// rather than epoll (StartRX blocks on the TAP fd, not KickFd) to exit.
	// Accessed atomically.
	stopping uint32

	// processorStarted records whether a ring processor goroutine is currently
	// running for this queue. It prevents a duplicate SET_VRING_KICK from
	// starting a second processor for the same virtqueue, which would
	// double-process descriptors and corrupt the used ring. Guarded by the
	// Server mutex that owns the VirtQueue.
	processorStarted bool
}

const (
	VRingDescSize   = 16
	VRingDescFNext  = 1
	VRingDescFWrite = 2
)

// virtio-blk request out-header (16 bytes, little-endian):
//   u32 type; u32 reserved; u64 sector
const virtioBlkOutHdrLen = 16

// ProcessRing waits for kicks and processes pending virtio-blk descriptors
// until Stop is called (via stopFd) or the kick fd is closed/hangs up.
func (vq *VirtQueue) ProcessRing(mem *Memory, blk *BlockDevice) {
	vq.runProcessor(func() bool {
		vq.processAvailable(mem, blk)
		return true
	}, "VirtQueue")
}

// runProcessor is the shared kick loop for blk (ProcessRing) and net (StartTX).
// It epoll-waits on KickFd + stopFd and invokes onKick each time the kick fd
// fires. Returns when stopped or the kick fd is gone. tag is for log messages.
//
// Why epoll + stopFd instead of a bare read on KickFd: closing an fd that is
// currently blocked in read() in another goroutine does NOT wake that read on
// Linux, so Server.stopProcessors cannot tear down a processor by closing
// KickFd. Epoll lets us watch a dedicated stop eventfd alongside KickFd.
func (vq *VirtQueue) runProcessor(onKick func() bool, tag string) {
	if vq.KickFd < 0 {
		return
	}
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		fmt.Printf("[%s %d] EpollCreate1 error: %v\n", tag, vq.Index, err)
		return
	}
	defer unix.Close(epfd)

	kickEv := &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(vq.KickFd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, vq.KickFd, kickEv); err != nil {
		fmt.Printf("[%s %d] EpollCtl add kick: %v\n", tag, vq.Index, err)
		return
	}
	if vq.stopFd >= 0 {
		stopEv := &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(vq.stopFd)}
		unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, vq.stopFd, stopEv)
	}

	events := make([]unix.EpollEvent, 4)
	buf := make([]byte, 8) // eventfd counter is 8 bytes
	for {
		n, err := unix.EpollWait(epfd, events, -1)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			fmt.Printf("[%s %d] EpollWait error: %v\n", tag, vq.Index, err)
			return
		}
		stopped := false
		for i := 0; i < n; i++ {
			switch int(events[i].Fd) {
			case vq.stopFd:
				stopped = true
			case vq.KickFd:
				// Drain the eventfd counter; ignore EAGAIN (level-triggered).
				for {
					_, e := syscall.Read(vq.KickFd, buf)
					if e != nil {
						if e == syscall.EAGAIN {
							break
						}
						if e == syscall.EINTR {
							continue
						}
						// fd closed (EOF, EBADF, etc.) — permanent.
						fmt.Printf("[%s %d] Kick FD read error: %v\n", tag, vq.Index, e)
						return
					}
					break
				}
				if (events[i].Events & unix.EPOLLHUP) != 0 {
					fmt.Printf("[%s %d] Kick FD hangup\n", tag, vq.Index)
					return
				}
				if !onKick() {
					return
				}
			}
		}
		if stopped {
			return
		}
	}
}

// isStopping reports whether Server has asked this queue's processors to exit.
// Used by loops that block on something other than KickFd (StartRX blocks on
// the TAP fd) so they can wake up between iterations and observe shutdown.
func (vq *VirtQueue) isStopping() bool {
	return atomic.LoadUint32(&vq.stopping) != 0
}

// markStopping signals all processors for this queue to exit. Safe to call
// concurrently with processor loops.
func (vq *VirtQueue) markStopping() {
	atomic.StoreUint32(&vq.stopping, 1)
	// Wake any processor blocked in epoll_wait on KickFd.
	if vq.stopFd >= 0 {
		event := []byte{1, 0, 0, 0, 0, 0, 0, 0}
		syscall.Write(vq.stopFd, event)
	}
}

// processAvailable drains all descriptors the guest has posted since the last
// scan. Reading the avail index once per kick is sufficient; if new buffers
// are posted concurrently the next kick will pick them up.
func (vq *VirtQueue) processAvailable(mem *Memory, blk *BlockDevice) {
	if vq.Num == 0 {
		// Queue size not configured (or SET_VRING_NUM rejected 0); modulo by
		// zero would panic. Bail out until the guest sets a valid size.
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
		if vq.Num == 0 {
			// processDescChain should not be reached with Num == 0, but guard
			// against it so a future caller cannot trigger a modulo-by-zero.
			return
		}
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
			if length < virtioBlkOutHdrLen {
				// Malformed request: out-header too short. Fail it instead of
				// continuing with zero reqType/sector, which would otherwise
				// be misinterpreted as VirtioBlkTIn (0) from sector 0.
				vq.completeRequest(mem, headIdx, 1)
				return
			}
			reqType = binary.LittleEndian.Uint32(buf[0:4])
			sector = binary.LittleEndian.Uint64(buf[8:16])
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
				// Write requests consume no host->guest data; the only byte
				// written back is the 1-byte status. Match the flush path.
				vq.completeRequest(mem, headIdx, 1)
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
//
// Memory ordering: the element bytes are written before the used index, and
// both happen-before usedMu.Unlock(). On the guest side, reading the new
// index therefore also observes the element. usedMu.Unlock provides the
// release fence needed on weakly-ordered architectures (ARM64), so we do not
// need a separate atomic store for the 16-bit index (sync/atomic has no
// Uint16 helper anyway).
func (vq *VirtQueue) completeRequest(mem *Memory, headIdx uint16, written uint32) {
	if vq.Num == 0 {
		return
	}
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

	// Publish the used index. Element stores above precede this store in
	// program order, and usedMu.Unlock() (via the defer above) issues a release
	// fence, so the guest cannot observe the new index without its element.
	binary.LittleEndian.PutUint16(usedIdxBytes, usedIdx+1)

	// Notify the guest by writing to CallFd (eventfd counter = 1).
	if vq.CallFd >= 0 {
		event := []byte{1, 0, 0, 0, 0, 0, 0, 0}
		syscall.Write(vq.CallFd, event)
	}
}
