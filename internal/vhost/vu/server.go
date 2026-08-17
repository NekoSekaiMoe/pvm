package vu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Server is a vhost-user backend serving one virtio-blk device on a unix
// socket. One frontend connection at a time; when the frontend goes away the
// session ends but the listener stays up (a re-booted guest can reconnect).
type Server struct {
	dev  *BlkDev
	ln   *net.UnixListener
	path string

	mu     sync.Mutex // guards session teardown
	sess   *session
	closed bool
	wg     sync.WaitGroup
}

// Serve binds socketPath and starts accepting. The socket file appears
// immediately (unlike a subprocess daemon there is no startup race).
func Serve(socketPath string, dev *BlkDev) (*Server, error) {
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("vu: listen %s: %w", socketPath, err)
	}
	s := &Server{dev: dev, ln: ln, path: socketPath}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// SocketPath returns the path the guest should connect to.
func (s *Server) SocketPath() string { return s.path }

// Close stops the listener and any active session.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.sess != nil {
		s.sess.close()
	}
	s.mu.Unlock()
	err := s.ln.Close()
	s.wg.Wait()
	os.Remove(s.path)
	return err
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			return // listener closed
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.sess = newSession(s.dev, newConn(c))
		sess := s.sess
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			sess.run()
		}()
	}
}

// session is one frontend connection.
type session struct {
	dev *BlkDev
	c   *conn

	mu       sync.Mutex
	mem      memTable
	vq       vring
	proto    uint64 // negotiated vhost-user protocol features
	status   uint64
	closed   bool
	pumpOnce sync.Once
}

func newSession(dev *BlkDev, c *conn) *session {
	return &session{dev: dev, c: c}
}

func (s *session) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.c.c.Close()
	s.mem.close()
	if s.vq.kick != nil {
		s.vq.kick.close()
	}
	if s.vq.call != nil {
		s.vq.call.close()
	}
	if s.vq.err != nil {
		s.vq.err.close()
	}
}

// run is the control-channel message loop.
func (s *session) run() {
	defer s.close()
	for {
		m, err := s.c.recv()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("vu: recv: %v", err)
			}
			return
		}
		replied, err := s.handle(m)
		if err != nil {
			log.Printf("vu: request %d: %v", m.request, err)
		}
		needReply := s.proto&(1<<protoFReplyAck) != 0 && m.flags&flagNeedReply != 0
		if !replied && needReply {
			v := uint64(0)
			if err != nil {
				v = 1
			}
			var p [8]byte
			binary.LittleEndian.PutUint64(p[:], v)
			if serr := s.c.reply(m, p[:]); serr != nil {
				return
			}
		}
		if err != nil && m.request == reqSetMemTable {
			return // a broken memory table is unrecoverable
		}
	}
}

// handle dispatches one message. It reports whether a reply was sent.
func (s *session) handle(m *msg) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m.request {
	case reqGetFeatures:
		var p [8]byte
		binary.LittleEndian.PutUint64(p[:], s.dev.features())
		return true, s.c.reply(m, p[:])

	case reqSetFeatures:
		// The frontend picks a subset of what we offered; nothing to do.
		return false, nil

	case reqSetOwner, reqResetOwner, reqSetLogFd:
		return false, nil

	case reqGetProtocolFeatures:
		var p [8]byte
		binary.LittleEndian.PutUint64(p[:], ourProtocolFeatures)
		return true, s.c.reply(m, p[:])

	case reqSetProtocolFeatures:
		s.proto = m.u64() & ourProtocolFeatures
		return false, nil

	case reqGetQueueNum:
		var p [8]byte
		binary.LittleEndian.PutUint64(p[:], 1)
		return true, s.c.reply(m, p[:])

	case reqSetMemTable:
		return false, s.mem.setMemTable(m.payload, m.fds)

	case reqSetVringNum:
		idx, num := m.vringState()
		if idx != 0 {
			return false, fmt.Errorf("only queue 0 supported (got %d)", idx)
		}
		s.vq.num = num
		return false, nil

	case reqSetVringAddr:
		a := m.vringAddr()
		if a.index != 0 {
			return false, fmt.Errorf("only queue 0 supported (got %d)", a.index)
		}
		return false, s.vq.setup(&s.mem, a)

	case reqSetVringBase:
		idx, base := m.vringState()
		if idx != 0 {
			return false, fmt.Errorf("only queue 0 supported")
		}
		s.vq.lastAvail = base
		return false, nil

	case reqGetVringBase:
		// Queue reset: frontend asks for last_avail_idx and stops the queue.
		var p [8]byte
		binary.LittleEndian.PutUint32(p[0:], 0)
		binary.LittleEndian.PutUint32(p[4:], uint32(s.vq.lastAvail))
		return true, s.c.reply(m, p[:])

	case reqSetVringKick:
		return false, s.setVringFile(m, &s.vq.kick)

	case reqSetVringCall:
		return false, s.setVringFile(m, &s.vq.call)

	case reqSetVringErr:
		return false, s.setVringFile(m, &s.vq.err)

	case reqSetVringEnable:
		idx, num := m.vringState()
		if idx != 0 {
			return false, fmt.Errorf("only queue 0 supported")
		}
		s.vq.enabled = num != 0
		if s.vq.enabled {
			s.maybeStartPump()
		}
		return false, nil

	case reqSetVringEndian:
		return false, nil // we only do little-endian; legacy flag, ignore

	case reqGetConfig:
		off := binary.LittleEndian.Uint32(m.payload[0:])
		sz := binary.LittleEndian.Uint32(m.payload[4:])
		data, err := s.dev.config(off, sz)
		if err != nil {
			return false, err
		}
		p := make([]byte, 12+len(data))
		copy(p[0:], m.payload[:12])
		copy(p[12:], data)
		return true, s.c.reply(m, p)

	case reqSetConfig:
		// No writable fields (we don't advertise CONFIG_WCE); accept & ignore.
		return false, nil

	case reqGetStatus:
		var p [8]byte
		binary.LittleEndian.PutUint64(p[:], s.status)
		return true, s.c.reply(m, p[:])

	case reqSetStatus:
		s.status = m.u64()
		return false, nil

	case reqGetSharedObject:
		return false, fmt.Errorf("shared object lookup unsupported")

	default:
		return false, fmt.Errorf("unknown request %d", m.request)
	}
}

// setVringFile handles KICK/CALL/ERR: payload u64 (index | NOFD), optional fd.
func (s *session) setVringFile(m *msg, dst **eventfd) error {
	u := m.u64()
	if u&vringNoFD != 0 {
		if *dst != nil {
			(*dst).close()
			*dst = nil
		}
		return nil
	}
	if len(m.fds) < 1 {
		return errors.New("vu: vring file message without fd")
	}
	fd := m.fds[0]
	// Take ownership: dup so later cleanup paths don't double-close fds
	// still referenced by the message.
	nfd, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(nfd), "vring-fd")
	if *dst != nil {
		(*dst).close()
	}
	*dst = &eventfd{f: f}
	if dst == &s.vq.kick {
		s.maybeStartPump()
	}
	return nil
}

// maybeStartPump launches the queue-processing goroutine once the queue is
// enabled AND the kick fd exists. Called from both SET_VRING_ENABLE and
// SET_VRING_KICK so either message order works; pumpOnce dedupes.
func (s *session) maybeStartPump() {
	if !s.vq.enabled || s.vq.kick == nil {
		return
	}
	s.pumpOnce.Do(func() {
		go s.pump()
	})
}

// pump waits for kicks and drains the avail ring.
func (s *session) pump() {
	for {
		s.mu.Lock()
		kick := s.vq.kick
		closed := s.closed
		s.mu.Unlock()
		if closed || kick == nil {
			return
		}
		if err := kick.wait(); err != nil {
			return
		}
		s.mu.Lock()
		for {
			e, err := s.vq.pop(&s.mem)
			if err != nil {
				log.Printf("vu: pop: %v", err)
				break
			}
			if e == nil {
				break
			}
			if err := e.translateSG(&s.mem); err != nil {
				log.Printf("vu: translate: %v", err)
				break
			}
			usedLen, err := s.dev.process(e)
			if err != nil {
				log.Printf("vu: blk request: %v", err)
				continue
			}
			if err := s.vq.push(e, usedLen); err != nil {
				log.Printf("vu: push: %v", err)
				break
			}
		}
		if err := s.vq.notify(); err != nil {
			log.Printf("vu: notify: %v", err)
		}
		s.mu.Unlock()
	}
}
