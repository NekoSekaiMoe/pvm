package vhost

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

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
// 1.x, all little-endian:
//
//	u64 capacity;   // total 512-byte sectors
//	u32 size_max;   // max single segment size
//	u32 seg_max;    // max segments in a request
//	u16 geometry_cylinders;
//	u8  geometry_heads;
//	u8  geometry_sectors;
//	u32 blk_size;   // only valid if VIRTIO_BLK_F_BLK_SIZE negotiated
//	u8  physical_block_exp;
//	u8  alignment_offset;
//	u16 min_io_size;
//	u32 opt_io_size;
//	u8  writeback;
//	u8  unused[3];
const (
	virtioBlkCfgLen      = 8 + 4 + 4 + 2 + 1 + 1 + 4 + 1 + 1 + 2 + 4 + 1 + 3
	virtioBlkCfgSizeMax  = 4096
	virtioBlkCfgSegMax   = 1
	virtioBlkCfgBlkSize  = 512
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
	// Stop any running ring processors and release kick/call fds so we do not
	// leak them (and so a re-created Server on the same path is clean).
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, vq := range s.queues {
		if vq == nil {
			continue
		}
		s.stopProcessorLocked(vq)
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			break
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
		fmt.Printf("[Vhost-User] writeU64Reply write error: %v\n", err)
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
		fmt.Printf("[Vhost-User] writePayloadReply write error: %v\n", err)
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
		fmt.Printf("[Vhost-User] writeAckReply write error: %v\n", err)
	}
}

func (s *Server) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	fmt.Println("[Vhost-User] Accepted new connection")

	b := make([]byte, 4096)
	oob := make([]byte, 4096)

	for {
		n, oobn, _, _, err := conn.ReadMsgUnix(b, oob)
		if err != nil {
			fmt.Printf("[Vhost-User] Read error: %v\n", err)
			break
		}

		if n < 12 {
			fmt.Println("[Vhost-User] Short read")
			continue
		}

		var hdr VhostUserMsgHeader
		if err := hdr.Decode(b[:12]); err != nil {
			fmt.Printf("[Vhost-User] Decode header error: %v\n", err)
			continue
		}

		payload := b[12:n]
		needReply := (hdr.Flags & VhostUserNeedReply) != 0
		fmt.Printf("[Vhost-User] Received Request: %d, Flags: 0x%x, Size: %d, oob: %d\n", hdr.Request, hdr.Flags, hdr.Size, oobn)

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

		switch hdr.Request {
		case VhostUserGetFeatures:
			var features uint64 = (1 << 32) | (1 << 24) // VIRTIO_F_VERSION_1 | VIRTIO_F_NOTIFY_ON_EMPTY
			if s.devType == deviceBlk {
				// VIRTIO_BLK_F_SIZE_MAX(1), F_SEG_MAX(2), F_BLK_SIZE(6), F_FLUSH(9).
				// F_BLK_SIZE is advertised because we fill blk_size in the config.
				features |= (1 << 1) | (1 << 2) | (1 << 6) | (1 << 9)
			} else if s.devType == deviceNet {
				// VIRTIO_NET_F_MAC(5), F_MRG_RXBUF(15), F_STATUS(16)
				features |= (1 << 5) | (1 << 15) | (1 << 16)
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
			// GET_CONFIG payload: u32 offset, u32 size, then up to size bytes
			// of current config (writeable region). We must return exactly
			// `size` bytes sliced from our config starting at `offset`.
			if len(payload) < 8 {
				s.writePayloadReply(hdr, []byte{}, conn)
				break
			}
			off := binary.LittleEndian.Uint32(payload[0:4])
			sz := binary.LittleEndian.Uint32(payload[4:8])

			cfg := s.buildDeviceConfig()
			resp := make([]byte, sz)
			if uint32(len(cfg)) >= off {
				n := copy(resp, cfg[off:])
				// Zero-fill the remainder if the requested window extends past
				// the config we expose (spec: return `size` bytes regardless).
				for i := n; i < len(resp); i++ {
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
						fmt.Printf("[Vhost-User] Mmap error: %v\n", err)
					}
				}
			}
			fmt.Printf("[Vhost-User] Mapped %d memory regions\n", numRegions)

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
				fmt.Printf("[Vhost-User] Rejecting invalid vring size %d for queue %d\n", num, idx)
				// Leave vq.Num unchanged; do not ack success if REPLY_ACK is
				// expected — fall through with a non-zero payload below.
				if needReply && s.replyAck {
					hdr.Flags |= VhostUserReplyMask
					hdr.Size = 8
					hdr.Encode(replyBuf[:12])
					binary.LittleEndian.PutUint64(replyBuf[12:20], 1) // 1 == error
					conn.Write(replyBuf[:20])
					replied = true
				}
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
			}
			// Start a processor for this queue exactly once. Re-receiving
			// SET_VRING_KICK without a prior stop would otherwise spawn a
			// second goroutine over the same virtqueue and double-process.
			start := !vq.processorStarted && vq.KickFd >= 0
			if start {
				vq.stopFd = newEventfd()
				vq.processorStarted = true
				atomic.StoreUint32(&vq.stopping, 0) // reset any prior stop flag
			}
			s.mu.Unlock()
			if start {
				fmt.Printf("[Vhost-User] Virtqueue %d Kick FD received, starting processor...\n", idx)
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
			fmt.Printf("[Vhost-User] Unhandled request %d\n", hdr.Request)
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
			fmt.Printf("[Vhost-User] blk.Size error in GET_CONFIG: %v\n", err)
		}
		capacity := uint64(0)
		if err == nil {
			capacity = uint64(size / 512)
		}
		binary.LittleEndian.PutUint64(cfg[0:8], capacity)
		binary.LittleEndian.PutUint32(cfg[8:12], virtioBlkCfgSizeMax)
		binary.LittleEndian.PutUint32(cfg[12:16], virtioBlkCfgSegMax)
		// cfg[16:20] geometry cylinders = 0
		// cfg[20]    geometry heads      = 0
		// cfg[21]    geometry sectors    = 0
		binary.LittleEndian.PutUint32(cfg[22:26], virtioBlkCfgBlkSize) // F_BLK_SIZE field
		// remaining fields default to 0
	}
	// Net has a MAC config too; we currently return zeros if not set.
	return cfg
}

// stopAllProcessors stops every running ring processor. Called before
// UnmapAll on re-negotiation so processors do not touch regions being torn
// down.
func (s *Server) stopAllProcessors() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, vq := range s.queues {
		if vq == nil {
			continue
		}
		s.stopProcessorLocked(vq)
	}
}

// stopProcessorLocked tears down a single queue's processor: signals stop,
// closes its kick/call/stop fds, and clears processorStarted so a future
// SET_VRING_KICK can start a fresh processor. Caller must hold s.mu.
func (s *Server) stopProcessorLocked(vq *VirtQueue) {
	if vq == nil {
		return
	}
	if vq.processorStarted {
		vq.markStopping()
	}
	// Closing the kick fd lets an in-flight epoll_wait return (the fd becomes
	// unreadable / hangs up) and prevents a re-armed wait. stopFd was already
	// written by markStopping to wake the epoll promptly.
	for _, fd := range []int{vq.KickFd, vq.CallFd, vq.stopFd} {
		if fd >= 0 {
			syscall.Close(fd)
		}
	}
	vq.KickFd = noFd
	vq.CallFd = noFd
	vq.stopFd = noFd
	vq.processorStarted = false
}

// newEventfd creates an eventfd used as a stop wakeup, or returns -1 on
// failure (processors treat -1 as "no stop fd" and still run).
func newEventfd() int {
	r0, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, 0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK, 0)
	if errno != 0 {
		fmt.Printf("[Vhost-User] eventfd creation failed: %v\n", errno)
		return noFd
	}
	return int(r0)
}
