package vhost

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// deviceType identifies which virtio device a Server is serving. vhost-user
// transports a single virtio device per socket, so blk and net MUST live on
// independent sockets — otherwise the server cannot tell which device the
// guest is talking to and the first feature negotiation would pin the type
// incorrectly.
type deviceType int

const (
	deviceBlk deviceType = iota + 1
	deviceNet
)

// Vhost-user protocol feature bits, as defined by the vhost-user spec
// (docs/interop/vhost-user.rst in QEMU). These MUST match the bit numbers the
// guest driver negotiates against — advertising the wrong bit makes the guest
// believe an unrelated feature is agreed and corrupts the rest of negotiation.
const (
	protoFReplyAck    = 1 << 3  // VHOST_USER_PROTOCOL_F_REPLY_ACK
	protoFMQ          = 1 << 0  // VHOST_USER_PROTOCOL_F_MQ
	protoFInbandNotif = 1 << 14 // VHOST_USER_PROTOCOL_F_INBAND_MESSAGES
	protoFConfig      = 1 << 9  // VHOST_USER_PROTOCOL_F_CONFIG
)

// maxQueues caps the queue index we will accept. The vhost-user transport
// allows the guest to request a queue by index; an unvalidated index would let
// the guest force us to allocate an arbitrarily large slice. 8 is well above
// what virtio-blk (1-2) or this virtio-net implementation (RX+TX = 2) need.
const maxQueues = 8

// virtio-blk config space fields we expose via GET_CONFIG. Layout per virtio
// 1.x (linux/virtio_blk.h), all little-endian:
//
//	u64 capacity;   // offset 0,  total 512-byte sectors
//	u32 size_max;   // offset 8,  max single segment size
//	u32 seg_max;    // offset 12, max segments in a request
//	u16 cylinders;  // offset 16, geometry
//	u8  heads;      // offset 18, geometry
//	u8  sectors;    // offset 19, geometry
//	u32 blk_size;   // offset 20, only valid if VIRTIO_BLK_F_BLK_SIZE negotiated
//	u8  physical_block_exp; // offset 24
//	u8  alignment_offset;   // offset 25
//	u16 min_io_size;        // offset 26
//	u32 opt_io_size;        // offset 28
//	u8  writeback;          // offset 32
//	u8  unused[3];          // offset 33
const (
	virtioBlkCfgLen     = 8 + 4 + 4 + 2 + 1 + 1 + 4 + 1 + 1 + 2 + 4 + 1 + 3
	virtioBlkCfgSizeMax = 4096
	virtioBlkCfgSegMax  = 1
	virtioBlkCfgBlkSize = 512
)

type Server struct {
	socketPath string
	listener   *net.UnixListener
	mem        *Memory
	devType    deviceType
	blk        *BlockDevice
	netDev     *NetDevice

	mu        sync.Mutex
	queues    []*VirtQueue
	numQueues uint32
	replyAck  bool
}

// NewServer creates a vhost-user server. Exactly one of blk / netDev must be
// non-nil; the server pins its device type from whichever is provided so
// feature negotiation and config reads are unambiguous.
func NewServer(socketPath string, blk *BlockDevice, netDev *NetDevice) *Server {
	var devType deviceType
	switch {
	case blk != nil:
		devType = deviceBlk
		netDev = nil
	case netDev != nil:
		devType = deviceNet
		blk = nil
	default:
		// Caller error; default to block semantics to preserve historic behavior.
		devType = deviceBlk
	}
	return &Server{
		socketPath: socketPath,
		mem:        &Memory{},
		devType:    devType,
		blk:        blk,
		netDev:     netDev,
		queues:     make([]*VirtQueue, 0, 2),
	}
}

// getQueue returns the queue at idx, or nil if idx is out of range. It grows
// the queue slice up to maxQueues only. Callers must hold s.mu and must handle
// a nil return (e.g. reject the request) instead of dereferencing blindly.
func (s *Server) getQueue(idx uint32) *VirtQueue {
	if idx >= maxQueues {
		return nil
	}
	for uint32(len(s.queues)) <= idx {
		s.queues = append(s.queues, &VirtQueue{Index: uint32(len(s.queues)), KickFd: noFd, CallFd: noFd, stopFd: noFd})
	}
	if s.queues[idx] == nil {
		s.queues[idx] = &VirtQueue{Index: idx, KickFd: noFd, CallFd: noFd, stopFd: noFd}
	}
	return s.queues[idx]
}

func (s *Server) Start() error {
	os.Remove(s.socketPath)
	addr, err := net.ResolveUnixAddr("unix", s.socketPath)
	if err != nil {
		return err
	}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	s.listener = l

	go s.acceptLoop()
	return nil
}

func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	// Stop any running ring processors and release kick/call/stop fds so we do
	// not leak them (and so a re-created Server on the same path is clean).
	s.mu.Lock()
	var waits []chan struct{}
	for _, vq := range s.queues {
		if vq == nil {
			continue
		}
		if ch := s.stopProcessorLocked(vq); ch != nil {
			waits = append(waits, ch)
		}
	}
	// Close the CallFds that stopProcessorLocked deliberately leaves alone.
	for _, vq := range s.queues {
		if vq != nil && vq.CallFd >= 0 {
			syscall.Close(vq.CallFd)
			vq.CallFd = noFd
		}
	}
	s.mu.Unlock()
	for _, ch := range waits {
		<-ch
	}
	s.waitAllIO() // in-flight IO must finish before the Server goes away
	if s.netDev != nil {
		s.netDev.Close()
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			break
		}
		// Log the peer's pid/uid via SO_PEERCRED so a connection that never
		// sends a vhost-user request can be attributed to the right process
		// (it is otherwise ambiguous whether the connecter is UML's
		// virtio_uml probe, mconsole, or something else). Zero cost when debug
		// logging is off except the one getsockopt per accept.
		if pid, uid, ok := peerCred(conn); ok {
			pkgLog.Infof("accepted new connection (peer pid=%d uid=%d)", pid, uid)
		} else {
			pkgLog.Infof("accepted new connection (peer cred unavailable)")
		}
		go s.handleConn(conn)
	}
}

// writeU64Reply sends a reply with a single u64 payload (used by GetFeatures,
// GetProtocolFeatures, GetQueueNum). Write errors and short writes are logged;
// a stalled reply would otherwise hang negotiation silently.
func (s *Server) writeU64Reply(hdr VhostUserMsgHeader, buf []byte, val uint64, conn *net.UnixConn) {
	hdr.Flags |= VhostUserReplyMask
	hdr.Size = 8
	hdr.Encode(buf[:12])
	binary.LittleEndian.PutUint64(buf[12:20], val)
	if _, err := conn.Write(buf[:20]); err != nil {
		pkgLog.Warnf("writeU64Reply write error: %v", err)
	}
}

// writePayloadReply sends a reply with an arbitrary payload (used by GetConfig,
// GetVringBase). Reports write errors instead of discarding them.
func (s *Server) writePayloadReply(hdr VhostUserMsgHeader, payload []byte, conn *net.UnixConn) {
	buf := make([]byte, 12+len(payload))
	hdr.Flags |= VhostUserReplyMask
	hdr.Size = uint32(len(payload))
	hdr.Encode(buf[:12])
	copy(buf[12:], payload)
	if _, err := conn.Write(buf); err != nil {
		pkgLog.Warnf("writePayloadReply write error: %v", err)
	}
}

// writeAckReply sends a REPLY_ACK response: the 12-byte header with the REPLY
// flag, followed by a u64 payload whose value is 0 for success (non-zero would
// signal an error). Per the vhost-user spec, when REPLY_ACK is negotiated the
// reply to a NEED_REPLY request carries this u64 — a bare header-only reply
// (size=0) is malformed and desyncs the protocol stream.
func (s *Server) writeAckReply(hdr VhostUserMsgHeader, buf []byte, conn *net.UnixConn) {
	hdr.Flags |= VhostUserReplyMask
	hdr.Size = 8 // u64 payload
	hdr.Encode(buf[:12])
	binary.LittleEndian.PutUint64(buf[12:20], 0) // 0 == success
	if _, err := conn.Write(buf[:20]); err != nil {
		pkgLog.Warnf("writeAckReply write error: %v", err)
	}
}

func (s *Server) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	// (peer pid/uid is logged in acceptLoop via SO_PEERCRED.)

	b := make([]byte, 4096)
	oob := make([]byte, 4096)

	for {
		// Probe for silent peers: set a read deadline so a guest that connects
		// but never sends (or whose bytes are not delivered) is surfaced in the
		// log as a timeout rather than vanishing into a blocking read. The
		// deadline is long enough not to trip on slow senders and is reset each
		// iteration after the read returns.
		conn.SetReadDeadline(timeNow().Add(10 * time.Second))
		n, oobn, _, _, err := conn.ReadMsgUnix(b, oob)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			if isTimeout(err) {
				pkgLog.Warnf("no data from peer in 10s (connection may be stale or peer is not a vhost-user client)")
				continue
			}
			pkgLog.Infof("read error: %v", err)
			break
		}
		pkgLog.Debugf("read n=%d oobn=%d", n, oobn)

		if n < 12 {
			pkgLog.Warnf("short read: %d bytes", n)
			continue
		}

		var hdr VhostUserMsgHeader
		if err := hdr.Decode(b[:12]); err != nil {
			pkgLog.Warnf("decode header error: %v", err)
			continue
		}

		payload := b[12:n]
		needReply := (hdr.Flags & VhostUserNeedReply) != 0
		pkgLog.Debugf("request=%d (%s) flags=0x%x size=%d oob=%d", hdr.Request, requestName(hdr.Request), hdr.Flags, hdr.Size, oobn)

		var fds []int
		if oobn > 0 {
			scmsgs, _ := syscall.ParseSocketControlMessage(oob[:oobn])
			for _, m := range scmsgs {
				rights, _ := syscall.ParseUnixRights(&m)
				fds = append(fds, rights...)
			}
		}

		replyBuf := make([]byte, 12+8) // header + up to 8 bytes payload for acks

		// replied tracks whether this request has already produced an explicit
		// reply below; it lets the fallback REPLY_ACK path skip requests that
		// were answered inline (GetFeatures, GetConfig, GetVringBase, ...).
		replied := false
		// fdConsumed counts how many of the received fds this request has
		// transferred to a VirtQueue or Memory object. Any fds beyond that are
		// stray (e.g. extra fds past numRegions, or fds on a request that takes
		// none) and MUST be closed so we never leak guest-passed descriptors.
		fdConsumed := 0

		switch hdr.Request {
		case VhostUserGetFeatures:
			var features uint64 = (1 << 32) | (1 << 24) // VIRTIO_F_VERSION_1 | VIRTIO_F_NOTIFY_ON_EMPTY
			features |= 1 << 30 // VHOST_USER_F_PROTOCOL_FEATURES: advertises we support the protocol-features negotiation step
			if s.devType == deviceBlk {
				// VIRTIO_BLK_F_SIZE_MAX(1), F_SEG_MAX(2), F_BLK_SIZE(6), F_FLUSH(9).
				// F_BLK_SIZE is advertised because we fill blk_size in the config.
				features |= (1 << 1) | (1 << 2) | (1 << 6) | (1 << 9)
			} else if s.devType == deviceNet {
				// VIRTIO_NET_F_MAC(5), F_MRG_RXBUF(15), F_STATUS(16)
				features |= (1 << 5) | (1 << 16)
			// (F_MRG_RXBUF bit 15 deliberately omitted: see comment above.)
			}
			s.writeU64Reply(hdr, replyBuf, features, conn)
			replied = true

		case VhostUserGetProtocolFeatures:
			// Advertise REPLY_ACK (and MQ for net) so the guest can use the
			// simplified ack path and query max queues. Blk also advertises
			// F_CONFIG so the guest knows it may issue GET_CONFIG.
			protoFeatures := uint64(protoFReplyAck | protoFConfig)
			if s.devType == deviceNet {
				protoFeatures |= protoFMQ | protoFInbandNotif
			}
			s.writeU64Reply(hdr, replyBuf, protoFeatures, conn)
			replied = true

		case VhostUserGetQueueNum:
			// Only meaningful when MQ protocol feature is negotiated (net).
			var nq uint64 = 1
			if s.devType == deviceNet {
				nq = 2 // RX + TX
			}
			s.writeU64Reply(hdr, replyBuf, nq, conn)
			replied = true

		case VhostUserSetOwner, VhostUserSetFeatures:
			// Ack / no-op.

		case VhostUserSetProtocolFeatures:
			if len(payload) >= 8 {
				pf := binary.LittleEndian.Uint64(payload[0:8])
				s.mu.Lock()
				s.replyAck = (pf & protoFReplyAck) != 0
				s.mu.Unlock()
			}

		case VhostUserGetConfig:
			replied = true
			// vhost_user_config request payload (12 bytes): u32 offset, u32 size,
			// u32 flags. Reply echoes the 12-byte header and appends `size` bytes
			// of config starting at `offset`.
			if len(payload) < 12 {
				s.writePayloadReply(hdr, []byte{}, conn)
				break
			}
			off := binary.LittleEndian.Uint32(payload[0:4])
			sz := binary.LittleEndian.Uint32(payload[4:8])
			// Cap size to avoid a malicious/huge guest value forcing a giant
			// allocation. The virtio-blk config space is tiny; anything past a
			// generous bound is treated as protocol garbage (empty reply).
			const maxConfigRead = 4096
			if sz > maxConfigRead {
				pkgLog.Warnf("GET_CONFIG size %d exceeds bound %d", sz, maxConfigRead)
				s.writePayloadReply(hdr, []byte{}, conn)
				break
			}

			cfg := s.buildDeviceConfig()
			resp := make([]byte, 12+sz)
			copy(resp[0:12], payload[0:12]) // echo the request header
			if uint32(len(cfg)) >= off {
				n := copy(resp[12:], cfg[off:])
				// Zero-fill remainder if the window extends past our config.
				for i := 12 + n; i < len(resp); i++ {
					resp[i] = 0
				}
			}
			s.writePayloadReply(hdr, resp, conn)

		case VhostUserSetMemTable:
			if len(payload) < 8 {
				continue
			}
			numRegions := binary.LittleEndian.Uint32(payload[0:4])
			if len(payload) < 8+int(numRegions)*32 {
				continue
			}
			// Stop all ring processors before tearing down the existing
			// mapping: they dereference mmap'd addresses, and Munmap'ing a
			// region out from under an in-flight request would be
			// use-after-unmap. Re-negotiation is rare (e.g. migration), so
			// paying stop+restart here is fine.
			s.stopAllProcessors()
			s.waitAllIO() // in-flight IO goroutines must finish before UnmapAll
			s.mem.UnmapAll() // clean up any regions from a previous negotiation
			for i := 0; i < int(numRegions); i++ {
				offset := 8 + i*32
				region := VhostUserMemoryRegion{
					GuestPhysAddr: binary.LittleEndian.Uint64(payload[offset : offset+8]),
					MemorySize:    binary.LittleEndian.Uint64(payload[offset+8 : offset+16]),
					UserspaceAddr: binary.LittleEndian.Uint64(payload[offset+16 : offset+24]),
					MmapOffset:    binary.LittleEndian.Uint64(payload[offset+24 : offset+32]),
				}
				if i < len(fds) {
					if err := s.mem.MapRegion(region, fds[i]); err != nil {
						pkgLog.Warnf("mmap region %d: %v", i, err)
					}
				}
			}
			pkgLog.Infof("mapped %d memory regions (prev processors stopped)", numRegions)
			fdConsumed = int(numRegions)
			if len(fds) < fdConsumed {
				fdConsumed = len(fds) // do not over-count missing fds
			}

		case VhostUserSetVringNum:
			if len(payload) < 8 {
				continue
			}
			idx := binary.LittleEndian.Uint32(payload[0:4])
			num := binary.LittleEndian.Uint32(payload[4:8])
			// Validate the queue size the guest requests: it must be nonzero
			// (we would otherwise divide by zero in modulo indexing), must not
			// exceed the virtio max (queue_merge_size / 2^15-ish; use 32768 as
			// a sane upper bound), and must be a power of two per the spec.
			if num == 0 || num > 32768 || (num&(num-1)) != 0 {
				pkgLog.Warnf("rejecting invalid vring size %d for queue %d", num, idx)
				// Leave vq.Num unchanged. Read replyAck under s.mu to avoid racing
				// VhostUserSetProtocolFeatures, and reuse writeU64Reply so write
				// errors are surfaced (the previous direct conn.Write dropped it).
				s.mu.Lock()
				rak := s.replyAck
				s.mu.Unlock()
				if needReply && rak {
					s.writeU64Reply(hdr, replyBuf, 1, conn) // payload=1 signals error
				}
				replied = needReply && rak
				break
			}
			s.mu.Lock()
			vq := s.getQueue(idx)
			if vq != nil {
				vq.Num = num
				if idx+1 > s.numQueues {
					s.numQueues = idx + 1
				}
			}
			s.mu.Unlock()

		case VhostUserSetVringBase:
			if len(payload) < 8 {
				continue
			}
			idx := binary.LittleEndian.Uint32(payload[0:4])
			base := binary.LittleEndian.Uint32(payload[4:8])
			s.mu.Lock()
			if vq := s.getQueue(idx); vq != nil {
				vq.LastAvail = uint16(base)
			}
			s.mu.Unlock()

		case VhostUserGetVringBase:
			// Per spec, GET_VRING_BASE tells the backend to STOP processing the
			// requested queue and reply with the current avail index as the
			// "last avail idx the guest need not process". Reply layout is the
			// 8-byte vhost_vring_state: u32 index, u32 num.
			replied = true
			if len(payload) < 4 {
				s.writePayloadReply(hdr, []byte{}, conn)
				break
			}
			idx := binary.LittleEndian.Uint32(payload[0:4])
			s.mu.Lock()
			vq := s.getQueue(idx)
			var last uint16
			if vq != nil {
				s.stopProcessorLocked(vq)
				last = vq.LastAvail
			}
			s.mu.Unlock()
			out := make([]byte, 8)
			binary.LittleEndian.PutUint32(out[0:4], idx)
			binary.LittleEndian.PutUint32(out[4:8], uint32(last))
			s.writePayloadReply(hdr, out, conn)

		case VhostUserSetVringAddr:
			if len(payload) < 32 {
				continue
			}
			idx := binary.LittleEndian.Uint32(payload[0:4])
			s.mu.Lock()
			if vq := s.getQueue(idx); vq != nil {
				vq.DescAddr = binary.LittleEndian.Uint64(payload[8:16])
				vq.UsedAddr = binary.LittleEndian.Uint64(payload[16:24])
				vq.AvailAddr = binary.LittleEndian.Uint64(payload[24:32])
			}
			s.mu.Unlock()

		case VhostUserSetVringEnable:
			// Payload: u32 index, u32 enable. No reply needed unless REPLY_ACK.

		case VhostUserSetVringCall:
			if len(payload) < 8 {
				continue
			}
			// payload is u64 where low 32 bits is the index.
			u64 := binary.LittleEndian.Uint64(payload[0:8])
			idx := uint32(u64 & 0xFFFFFFFF)
			s.mu.Lock()
			if len(fds) > 0 {
				if vq := s.getQueue(idx); vq != nil {
					// Close any prior CallFd before replacing it; otherwise
					// repeated SET_VRING_CALL (re-negotiation, migration)
					// leaks the old fd.
					if vq.CallFd >= 0 && vq.CallFd != fds[0] {
						syscall.Close(vq.CallFd)
					}
					vq.CallFd = fds[0]
					fdConsumed = 1
				}
			}
			s.mu.Unlock()

		case VhostUserSetVringKick:
			if len(payload) < 8 {
				continue
			}
			u64 := binary.LittleEndian.Uint64(payload[0:8])
			idx := uint32(u64 & 0xFFFFFFFF)
			s.mu.Lock()
			vq := s.getQueue(idx)
			if vq == nil {
				s.mu.Unlock()
				break
			}
			if len(fds) > 0 {
				// Close the prior KickFd before replacing (same reason as Call).
				if vq.KickFd >= 0 && vq.KickFd != fds[0] {
					// Stop the processor that is polling the old kick fd before
					// we close it, then start fresh on the new fd below.
					s.stopProcessorLocked(vq)
					syscall.Close(vq.KickFd)
				}
				vq.KickFd = fds[0]
				fdConsumed = 1
			}
			// Start a processor for this queue exactly once. Re-receiving
			// SET_VRING_KICK without a prior stop would otherwise spawn a
			// second goroutine over the same virtqueue and double-process.
			start := !vq.processorStarted && vq.KickFd >= 0
			if start {
				vq.stopFd = newEventfd()
				vq.done = make(chan struct{})
				if vq.ioSem == nil {
					vq.ioSem = make(chan struct{}, 32) // bound concurrent IO goroutines
				}
				vq.processorStarted = true
				atomic.StoreUint32(&vq.stopping, 0) // reset any prior stop flag
			}
			s.mu.Unlock()
			if start {
				pkgLog.Infof("virtqueue %d kick fd received, starting processor", idx)
				if s.devType == deviceBlk && s.blk != nil {
					go vq.ProcessRing(s.mem, s.blk)
				} else if s.devType == deviceNet && s.netDev != nil {
					if idx == 0 {
						go s.netDev.StartRX(vq, s.mem)
					} else if idx == 1 {
						go s.netDev.StartTX(vq, s.mem)
					}
				}
			}

		default:
			pkgLog.Debugf("unhandled request %d", hdr.Request)
		}

		// Close any received fds this request did not claim. Guest-passed fds
		// are otherwise leaked on every request that carries extras (or that we
		// do not handle). Ownership of consumed fds moved to a VirtQueue/Memory.
		for i := fdConsumed; i < len(fds); i++ {
			if fds[i] >= 0 {
				syscall.Close(fds[i])
			}
		}

		// REPLY_ACK fallback: only when the guest actually negotiated
		// REPLY_ACK AND set NEED_REPLY AND we did not already answer inline.
		// The reply is a header + u64 payload (0 = success), per spec — not a
		// bare header-only message.
		if needReply && !replied {
			s.mu.Lock()
			negotiated := s.replyAck
			s.mu.Unlock()
			if negotiated {
				s.writeAckReply(hdr, replyBuf, conn)
			}
		}
	}
}

// buildDeviceConfig returns the full device configuration space for GET_CONFIG.
// The caller slices it by the requested offset/size.
func (s *Server) buildDeviceConfig() []byte {
	cfg := make([]byte, virtioBlkCfgLen)
	if s.devType == deviceBlk && s.blk != nil {
		size, err := s.blk.Size()
		if err != nil {
			// Surface the error rather than silently reporting a zero capacity
			// disk (the guest would refuse to probe with
			// "Couldn't determine size of device's file").
			pkgLog.Warnf("blk.Size error in GET_CONFIG: %v", err)
		}
		capacity := uint64(0)
		if err == nil {
			capacity = uint64(size / 512)
		}
		binary.LittleEndian.PutUint64(cfg[0:8], capacity)
		binary.LittleEndian.PutUint32(cfg[8:12], virtioBlkCfgSizeMax)
		binary.LittleEndian.PutUint32(cfg[12:16], virtioBlkCfgSegMax)
		// cfg[16:18] geometry cylinders (u16) = 0
		// cfg[18]    geometry heads      (u8) = 0
		// cfg[19]    geometry sectors    (u8) = 0
		binary.LittleEndian.PutUint32(cfg[20:24], virtioBlkCfgBlkSize) // F_BLK_SIZE field
		// remaining fields default to 0
	}
	// Net has a MAC config too; we currently return zeros if not set.
	return cfg
}

// stopAllProcessors stops every running ring processor and waits for all
// of them to exit before returning. Called before UnmapAll on re-negotiation
// so processors cannot touch regions being torn down (use-after-unmap). The
// wait happens outside s.mu to avoid blocking other callers while a slow
// processor drains.
func (s *Server) stopAllProcessors() {
	s.mu.Lock()
	var waits []chan struct{}
	for _, vq := range s.queues {
		if vq == nil {
			continue
		}
		if ch := s.stopProcessorLocked(vq); ch != nil {
			waits = append(waits, ch)
		}
	}
	s.mu.Unlock()
	for _, ch := range waits {
		<-ch
	}
}

// waitAllIO blocks until every in-flight virtio-blk IO goroutine has finished.
// Called after stopAllProcessors (so no new IO is dispatched) and before
// UnmapAll so a completing read/write cannot touch a region that is about to
// be munmap'd. The per-queue WaitIO is cheap when nothing is in flight.
func (s *Server) waitAllIO() {
	s.mu.Lock()
	queues := append([]*VirtQueue(nil), s.queues...)
	s.mu.Unlock()
	for _, vq := range queues {
		if vq != nil {
			vq.WaitIO()
		}
	}
}

// stopProcessorLocked signals a single queue's processor to stop and returns
// its done channel (nil if no processor was running). It closes the
// processor-owned fds (KickFd, stopFd) but PRESERVES CallFd: the call fd is
// installed by SET_VRING_CALL and its lifetime belongs to Server.Stop, not to
// per-queue processor restart. The caller is responsible for waiting on the
// returned channel OUTSIDE s.mu before assuming the goroutine has exited.
// Caller must hold s.mu.
func (s *Server) stopProcessorLocked(vq *VirtQueue) chan struct{} {
	if vq == nil {
		return nil
	}
	var done chan struct{}
	if vq.processorStarted {
		vq.markStopping()
		done = vq.done
	}
	// Close only the fds the processor itself owns. KickFd lets an in-flight
	// epoll_wait observe hangup; stopFd was already written by markStopping.
	for _, fd := range []int{vq.KickFd, vq.stopFd} {
		if fd >= 0 {
			syscall.Close(fd)
		}
	}
	vq.KickFd = noFd
	vq.stopFd = noFd
	// Leave CallFd untouched; Server.Stop closes it during full teardown.
	vq.processorStarted = false
	// done is reset when a new processor starts (see SET_VRING_KICK).
	return done
}

// requestName maps a vhost-user request code to a human-readable label for
// debug logs. Unknown requests fall back to their numeric value.
func requestName(req uint32) string {
	switch req {
	case VhostUserNone:
		return "NONE"
	case VhostUserGetFeatures:
		return "GET_FEATURES"
	case VhostUserSetFeatures:
		return "SET_FEATURES"
	case VhostUserSetOwner:
		return "SET_OWNER"
	case VhostUserResetOwner:
		return "RESET_OWNER"
	case VhostUserSetMemTable:
		return "SET_MEM_TABLE"
	case VhostUserSetVringNum:
		return "SET_VRING_NUM"
	case VhostUserSetVringAddr:
		return "SET_VRING_ADDR"
	case VhostUserSetVringBase:
		return "SET_VRING_BASE"
	case VhostUserGetVringBase:
		return "GET_VRING_BASE"
	case VhostUserSetVringKick:
		return "SET_VRING_KICK"
	case VhostUserSetVringCall:
		return "SET_VRING_CALL"
	case VhostUserSetVringErr:
		return "SET_VRING_ERR"
	case VhostUserGetProtocolFeatures:
		return "GET_PROTO_FEATURES"
	case VhostUserSetProtocolFeatures:
		return "SET_PROTO_FEATURES"
	case VhostUserGetQueueNum:
		return "GET_QUEUE_NUM"
	case VhostUserSetVringEnable:
		return "SET_VRING_ENABLE"
	case VhostUserGetConfig:
		return "GET_CONFIG"
	case VhostUserSetConfig:
		return "SET_CONFIG"
	}
	return fmt.Sprintf("REQ_%d", req)
}

// newEventfd creates an eventfd used as a stop wakeup, or returns -1 on
// failure (processors treat -1 as "no stop fd" and still run).
func newEventfd() int {
	r0, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, 0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK, 0)
	if errno != 0 {
		pkgLog.Warnf("eventfd creation failed: %v", errno)
		return noFd
	}
	return int(r0)
}

// peerCred returns the (pid, uid, ok) of the process on the other end of a
// connected AF_UNIX socket via SO_PEERCRED (Linux). ok is false when the fd
// cannot be introspected (e.g. a non-Linux build path); callers log the
// ambiguous case rather than failing.
func peerCred(conn *net.UnixConn) (int, int, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var cred *unix.Ucred
	if err := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, false
	}
	if err != nil || cred == nil {
		return 0, 0, false
	}
	return int(cred.Pid), int(cred.Uid), true
}

// timeNow is the standard time.Now, wrapped so tests can stub it if needed.
func timeNow() time.Time { return time.Now() }

// isTimeout reports whether err is a net deadline/timeout error, used by the
// ReadMsgUnix probe to distinguish a silent peer from a real read error.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	return isTimeoutType(err)
}

// isTimeoutType unwraps err to a *net.OpError and checks its Timeout flag.
func isTimeoutType(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
