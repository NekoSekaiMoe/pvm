package vhost

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
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

// Vhost-user protocol feature bits (VHOST_USER_GET_PROTOCOL_FEATURES).
const (
	protoFReplyAck    = 1 << 3 // VHOST_USER_PROTOCOL_F_REPLY_ACK
	protoFMQ          = 1 << 4 // VHOST_USER_PROTOCOL_F_MQ
	protoFInbandNotif = 1 << 6 // VHOST_USER_PROTOCOL_F_INBAND_NOTIFY
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

// getQueue returns the queue at idx, allocating slots as needed. Callers
// must hold s.mu.
func (s *Server) getQueue(idx uint32) *VirtQueue {
	for uint32(len(s.queues)) <= idx {
		s.queues = append(s.queues, &VirtQueue{Index: uint32(len(s.queues))})
	}
	if s.queues[idx] == nil {
		s.queues[idx] = &VirtQueue{Index: idx}
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
// GetProtocolFeatures, GetQueueNum).
func (s *Server) writeU64Reply(hdr VhostUserMsgHeader, buf []byte, val uint64, conn *net.UnixConn) {
	hdr.Flags |= VhostUserReplyMask
	hdr.Size = 8
	hdr.Encode(buf[:12])
	binary.LittleEndian.PutUint64(buf[12:20], val)
	conn.Write(buf[:20])
}

// writePayloadReply sends a reply with an arbitrary payload (used by GetConfig).
func (s *Server) writePayloadReply(hdr VhostUserMsgHeader, payload []byte, conn *net.UnixConn) {
	buf := make([]byte, 12+len(payload))
	hdr.Flags |= VhostUserReplyMask
	hdr.Size = uint32(len(payload))
	hdr.Encode(buf[:12])
	copy(buf[12:], payload)
	conn.Write(buf)
}

// writeEmptyReply sends a header-only reply (used for REPLY_ACK).
func (s *Server) writeEmptyReply(hdr VhostUserMsgHeader, conn *net.UnixConn) {
	hdr.Flags |= VhostUserReplyMask
	hdr.Size = 0
	buf := make([]byte, 12)
	hdr.Encode(buf)
	conn.Write(buf)
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

		replyBuf := make([]byte, 12+8) // header + up to 8 bytes payload for simple acks

		switch hdr.Request {
		case VhostUserGetFeatures:
			var features uint64 = (1 << 32) | (1 << 24) // VIRTIO_F_VERSION_1 | VIRTIO_F_NOTIFY_ON_EMPTY
			if s.devType == deviceBlk {
				// VIRTIO_BLK_F_SIZE_MAX(1), F_SEG_MAX(2), F_BLK_SIZE(6), F_FLUSH(9)
				features |= (1 << 1) | (1 << 2) | (1 << 6) | (1 << 9)
			} else if s.devType == deviceNet {
				// VIRTIO_NET_F_MAC(5), F_MRG_RXBUF(15), F_STATUS(16)
				features |= (1 << 5) | (1 << 15) | (1 << 16)
			}
			s.writeU64Reply(hdr, replyBuf, features, conn)

		case VhostUserGetProtocolFeatures:
			// Advertise REPLY_ACK (and MQ for net) so the guest can use the
			// simplified ack path and query max queues.
			protoFeatures := uint64(protoFReplyAck | protoFInbandNotif)
			if s.devType == deviceNet {
				protoFeatures |= protoFMQ
			}
			s.writeU64Reply(hdr, replyBuf, protoFeatures, conn)

		case VhostUserGetQueueNum:
			// Only meaningful when MQ protocol feature is negotiated (net).
			var n uint64 = 1
			if s.devType == deviceNet {
				n = 2 // RX + TX
			}
			s.writeU64Reply(hdr, replyBuf, n, conn)

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
			// virtio-blk configuration space. Layout (virtio 1.x, all LE):
			//   u64 capacity;   // total sectors (512-byte)
			//   u32 size_max;
			//   u32 seg_max;
			//   ... (geometry, blk_size, writeback, etc.)
			// Without a valid capacity the guest refuses to probe the disk
			// ("Couldn't determine size"). We serve this only for block devices.
			if s.devType == deviceBlk && s.blk != nil {
				size, _ := s.blk.Size()
				capacity := uint64(size / 512)
				cfg := make([]byte, 8+4+4) // capacity + size_max + seg_max
				binary.LittleEndian.PutUint64(cfg[0:8], capacity)
				binary.LittleEndian.PutUint32(cfg[8:12], 4096) // size_max
				binary.LittleEndian.PutUint32(cfg[12:16], 1)   // seg_max
				s.writePayloadReply(hdr, cfg, conn)
			} else {
				// Net has a MAC config too; return zeros if not set.
				s.writePayloadReply(hdr, make([]byte, 8), conn)
			}

		case VhostUserSetMemTable:
			if len(payload) < 8 {
				continue
			}
			numRegions := binary.LittleEndian.Uint32(payload[0:4])
			if len(payload) < 8+int(numRegions)*32 {
				continue
			}
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
			s.mu.Lock()
			vq := s.getQueue(idx)
			vq.Num = num
			if idx+1 > s.numQueues {
				s.numQueues = idx + 1
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
			// Reply with the current avail index for the requested queue,
			// signaling "stop" to the guest. Payload: u32 index; reply u32 index.
			if len(payload) < 4 {
				continue
			}
			idx := binary.LittleEndian.Uint32(payload[0:4])
			s.mu.Lock()
			vq := s.getQueue(idx)
			last := uint16(0)
			if vq != nil {
				last = vq.LastAvail
			}
			s.mu.Unlock()
			s.writePayloadReply(hdr, []byte{byte(last), byte(last >> 8), 0, 0}, conn)

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
			var vq *VirtQueue
			s.mu.Lock()
			if len(fds) > 0 {
				vq = s.getQueue(idx)
				vq.KickFd = fds[0]
			}
			s.mu.Unlock()
			if vq != nil {
				// Virtqueue is ready. Start the ring processor outside the lock.
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

		// REPLY_ACK: if the guest set the NEED_REPLY flag on a request we did
		// not explicitly answer above, send an empty header-only reply.
		if needReply && hdr.Request != VhostUserGetFeatures &&
			hdr.Request != VhostUserGetProtocolFeatures &&
			hdr.Request != VhostUserGetQueueNum &&
			hdr.Request != VhostUserGetConfig &&
			hdr.Request != VhostUserGetVringBase {
			s.writeEmptyReply(hdr, conn)
		}
	}
}
