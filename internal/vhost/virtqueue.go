package vhost

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"syscall"

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

	// done is closed by the ring processor goroutine when it exits. Server
	// waits on it in stopProcessor before closing fds or tearing down memory,
	// so SET_MEM_TABLE can prove no goroutine still touches a region before
	// UnmapAll. nil until a processor starts.
	done chan struct{}

	// stopping is set by Server.stopProcessor to signal RX/TX loops that poll
	// rather than epoll (StartRX blocks on the TAP fd, not KickFd) to exit.
	// Accessed atomically.
	stopping uint32

	// ioWG tracks in-flight virtio-blk IO goroutines (one per request) so that
	// SET_MEM_TABLE / Server.Stop can prove none of them still touches a
	// mmap'd guest region before UnmapAll. Each IO goroutine does Add(1)
	// before starting and Done() when completeRequest has published; the
	// Server waits on it after stopping ring processors and before UnmapAll.
	ioWG sync.WaitGroup

	// ioSem caps concurrent virtio-blk IO goroutines per queue so a flood of
	// requests (e.g. dd) cannot spawn unbounded goroutines. nil == unlimited
	// (e.g. before the queue is fully configured); set by Server when the
	// processor starts.
	ioSem chan struct{}

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
	defer vq.signalDone()
	if vq.KickFd < 0 {
		return
	}
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		pkgLog.Warnf("[%s %d] EpollCreate1 error: %v", tag, vq.Index, err)
		return
	}
	defer unix.Close(epfd)

	kickEv := &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(vq.KickFd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, vq.KickFd, kickEv); err != nil {
		pkgLog.Warnf("[%s %d] EpollCtl add kick: %v", tag, vq.Index, err)
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
			pkgLog.Warnf("[%s %d] EpollWait error: %v", tag, vq.Index, err)
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
						pkgLog.Infof("[%s %d] Kick FD read error: %v", tag, vq.Index, e)
						return
					}
					break
				}
				if (events[i].Events & unix.EPOLLHUP) != 0 {
					pkgLog.Infof("[%s %d] Kick FD hangup", tag, vq.Index)
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

// signalDone marks the processor goroutine as finished. It is called via
// defer from runProcessor and from StartRX so Server.waitProcessor can observe
// exit without racing the goroutine's teardown. Safe to call when done is nil
// (e.g. a processor that never started).
func (vq *VirtQueue) signalDone() {
	vq.usedMu.Lock()
	ch := vq.done
	vq.usedMu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		default:
			close(ch)
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
			vq.completeRequest(mem, headIdx, vq.statusLen(statusSlice))
			return
		}
		iter++

		descBytes, err := mem.GuestToHost(vq.DescAddr+uint64(currIdx)*VRingDescSize, VRingDescSize)
		if err != nil {
			pkgLog.Warnf("[vq %d] failed to map desc %d", vq.Index, currIdx)
			return
		}

		addr := binary.LittleEndian.Uint64(descBytes[0:8])
		length := binary.LittleEndian.Uint32(descBytes[8:12])
		flags := binary.LittleEndian.Uint16(descBytes[12:14])
		next := binary.LittleEndian.Uint16(descBytes[14:16])

		buf, err := mem.GuestToHost(addr, uint64(length))
		if err != nil {
			pkgLog.Warnf("[vq %d] failed to map desc buf at 0x%x", vq.Index, addr)
			return
		}

		if isFirst {
			// virtio-blk out-header: u32 type, u32 reserved, u64 sector.
			if length < virtioBlkOutHdrLen {
				// Malformed request: out-header too short. Fail it instead of
				// continuing with zero reqType/sector, which would otherwise
				// be misinterpreted as VirtioBlkTIn (0) from sector 0.
				vq.completeRequest(mem, headIdx, vq.statusLen(statusSlice))
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
			// Read from disk into guest memory. Synchronous pread into each data
			// slice (see readvSync for why not io_uring). Bounded by ioSem and
			// tracked by ioWG so SET_MEM_TABLE cannot Munmap a region an in-flight
			// read still writes into.
			vq.startIO()
			go func() {
				defer vq.endIO()
				st := byte(VirtioBlkSOk)
				n := readvSync(blk, dataSlices, offset)
				if n < 0 {
					st = VirtioBlkSIoErr
					n = 0
				}
				written := uint32(n)
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = st
					written++ // +1 for the status byte
				}
				vq.completeRequest(mem, headIdx, written)
			}()
			return

		case VirtioBlkTOut:
			// Write from guest memory to disk. Synchronous pwrite per slice.
			vq.startIO()
			go func() {
				defer vq.endIO()
				st := byte(VirtioBlkSOk)
				if writevSync(blk, dataSlices, offset) < 0 {
					st = VirtioBlkSIoErr
				}
				var written uint32
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = st
					written = 1 // the 1-byte status only
				}
				vq.completeRequest(mem, headIdx, written)
			}()
			return

		case VirtioBlkTFlush:
			vq.startIO()
			go func() {
				defer vq.endIO()
				st := byte(VirtioBlkSOk)
				if err := blk.Sync(); err != nil {
					st = VirtioBlkSIoErr
				}
				var written uint32
				if statusSlice != nil && len(statusSlice) >= 1 {
					statusSlice[0] = st
					written = 1
				}
				vq.completeRequest(mem, headIdx, written)
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

// readvSync reads from blk at offset into each data slice in order,
// emulating preadv with synchronous pread. Returns the total bytes read, or -1
// on error. We use this instead of io_uring Preadv because iouring-go's Preadv
// builds the iovec array as a local variable and stores only a raw pointer to
// it in the SQE; the closure does not retain the slice, so a GC cycle between
// submit and kernel consumption leaves a dangling iovec pointer. Synchronous
// pread has no such lifetime hazard and the buffers are stable guest mmap
// pages for the duration.
func readvSync(blk *BlockDevice, bufs [][]byte, offset int64) int {
	total := 0
	for _, b := range bufs {
		n, err := blk.ReadAt(b, offset+int64(total))
		total += n
		if err != nil {
			return -1
		}
	}
	return total
}

// writevSync writes each data slice to blk at offset in order, emulating
// pwritev with synchronous pwrite. Returns the total bytes written, or -1 on
// error. See readvSync for why not io_uring.
func writevSync(blk *BlockDevice, bufs [][]byte, offset int64) int {
	total := 0
	for _, b := range bufs {
		n, err := blk.WriteAt(b, offset+int64(total))
		total += n
		if err != nil {
			return -1
		}
	}
	return total
}

// startIO reserves an IO slot (bounded by ioSem if configured) and registers
// the goroutine on ioWG so the Server can wait for in-flight IO before
// unmapping guest memory. It must be paired 1:1 with endIO (use defer). If the
// semaphore is nil (queue not fully configured) the goroutine runs unbounded,
// which is acceptable for the rare early path.
func (vq *VirtQueue) startIO() {
	if vq.ioSem != nil {
		vq.ioSem <- struct{}{}
	}
	vq.ioWG.Add(1)
}

// endIO releases the IO slot and marks the goroutine done. Always called via
// defer from the IO handler so both success and error paths release resources.
func (vq *VirtQueue) endIO() {
	vq.ioWG.Done()
	if vq.ioSem != nil {
		<-vq.ioSem
	}
}

// WaitIO blocks until every in-flight virtio-blk IO goroutine for this queue
// has finished. The Server calls this after stopping the ring processor (so no
// new IO is dispatched) and before UnmapAll, guaranteeing no goroutine still
// touches a region that is about to be munmap'd.
func (vq *VirtQueue) WaitIO() {
	vq.ioWG.Wait()
}

// statusLen returns 1 if the status byte descriptor was successfully
// captured (so the completion should report the single status byte as
// written), else 0. Used by error paths where no data was transferred so the
// reported used length matches what the guest expects to find in the used
// element.
func (vq *VirtQueue) statusLen(statusSlice []byte) uint32 {
	if statusSlice != nil && len(statusSlice) >= 1 {
		return 1
	}
	return 0
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

	// used ring header: flags(2), idx(2), ring(num*8), avail_event(2)
	usedIdxBytes, err := mem.GuestToHost(vq.UsedAddr+2, 2)
	if err != nil {
		vq.usedMu.Unlock()
		return
	}
	usedIdx := binary.LittleEndian.Uint16(usedIdxBytes)

	// elem is 8 bytes: id(4), len(4)
	elemOffset := uint64(4 + (int(usedIdx)%int(vq.Num))*8)
	elemBytes, err := mem.GuestToHost(vq.UsedAddr+elemOffset, 8)
	if err != nil {
		vq.usedMu.Unlock()
		return
	}
	binary.LittleEndian.PutUint32(elemBytes[0:4], uint32(headIdx))
	binary.LittleEndian.PutUint32(elemBytes[4:8], written)

	// Publish the used index. Element stores above precede this store in
	// program order; the Unlock below issues a release fence so the guest
	// cannot observe the new index without its element.
	binary.LittleEndian.PutUint16(usedIdxBytes, usedIdx+1)

	// Release the mutex BEFORE the guest notification: the release fence on
	// Unlock publishes the element+index writes, and holding the lock across
	// an eventfd write needlessly blocks other completions.
	vq.usedMu.Unlock()

	// Notify the guest by writing to CallFd (eventfd counter = 1).
	if vq.CallFd >= 0 {
		event := []byte{1, 0, 0, 0, 0, 0, 0, 0}
		syscall.Write(vq.CallFd, event)
	}
}
