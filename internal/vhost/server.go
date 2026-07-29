package vhost

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
)

type Server struct {
	socketPath string
	listener   *net.UnixListener
	mem        *Memory
	queues     []*VirtQueue
	blk        *BlockDevice
}

func NewServer(socketPath string, blk *BlockDevice) *Server {
	return &Server{
		socketPath: socketPath,
		mem:        &Memory{},
		queues:     make([]*VirtQueue, 2),
		blk:        blk,
	}
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
			var features uint64 = (1 << 32) | (1 << 30) | (1 << 1) | (1 << 2) | (1 << 6) | (1 << 9)
			hdr.Flags |= VhostUserReplyMask
			hdr.Size = 8
			hdr.Encode(replyBuf[:12])
			binary.LittleEndian.PutUint64(replyBuf[12:20], features)
			conn.Write(replyBuf)

		case VhostUserGetProtocolFeatures:
			var protoFeatures uint64 = 0
			hdr.Flags |= VhostUserReplyMask
			hdr.Size = 8
			hdr.Encode(replyBuf[:12])
			binary.LittleEndian.PutUint64(replyBuf[12:20], protoFeatures)
			conn.Write(replyBuf)

		case VhostUserGetQueueNum:
			hdr.Flags |= VhostUserReplyMask
			hdr.Size = 8
			hdr.Encode(replyBuf[:12])
			binary.LittleEndian.PutUint64(replyBuf[12:20], 1)
			conn.Write(replyBuf)

		case VhostUserSetOwner, VhostUserSetFeatures, VhostUserSetProtocolFeatures:
			// Ack

		case VhostUserSetMemTable:
			numRegions := binary.LittleEndian.Uint32(payload[0:4])
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
			idx := binary.LittleEndian.Uint32(payload[0:4])
			num := binary.LittleEndian.Uint32(payload[4:8])
			if s.queues[idx] == nil {
				s.queues[idx] = &VirtQueue{Index: idx}
			}
			s.queues[idx].Num = num

		case VhostUserSetVringBase:
			idx := binary.LittleEndian.Uint32(payload[0:4])
			base := binary.LittleEndian.Uint32(payload[4:8])
			if s.queues[idx] != nil {
				s.queues[idx].LastAvail = uint16(base)
			}

		case VhostUserSetVringAddr:
			idx := binary.LittleEndian.Uint32(payload[0:4])
			if s.queues[idx] != nil {
				s.queues[idx].DescAddr = binary.LittleEndian.Uint64(payload[8:16])
				s.queues[idx].UsedAddr = binary.LittleEndian.Uint64(payload[16:24])
				s.queues[idx].AvailAddr = binary.LittleEndian.Uint64(payload[24:32])
			}

		case VhostUserSetVringCall:
			// payload is u64 where lower 32 bit is index.
			u64 := binary.LittleEndian.Uint64(payload[0:8])
			idx := uint32(u64 & 0xFFFFFFFF)
			if len(fds) > 0 && s.queues[idx] != nil {
				s.queues[idx].CallFd = fds[0]
			}

		case VhostUserSetVringKick:
			u64 := binary.LittleEndian.Uint64(payload[0:8])
			idx := uint32(u64 & 0xFFFFFFFF)
			if len(fds) > 0 && s.queues[idx] != nil {
				s.queues[idx].KickFd = fds[0]
				// Virtqueue is ready! Start processing ring in background
				fmt.Printf("[Vhost-User] Virtqueue %d Kick FD received, starting processor...\n", idx)
				go s.queues[idx].ProcessRing(s.mem, s.blk)
			}

		default:
			fmt.Printf("[Vhost-User] Unhandled request %d\n", hdr.Request)
			if (hdr.Flags & VhostUserNeedReply) != 0 {
				hdr.Flags |= VhostUserReplyMask
				hdr.Size = 0
				hdr.Encode(replyBuf[:12])
				conn.Write(replyBuf[:12])
			}
		}

		_ = payload // ignore for now
	}
}
