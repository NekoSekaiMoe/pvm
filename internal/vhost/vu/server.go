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
	// ListenUnix applies the process umask; a permissive umask would expose
	// the control channel (memory-table fd passing) to other local users.
	// Only the guest frontend may talk to it.
	if err := os.Chmod(socketPath, 0600); err != nil {
		ln.Close()
		os.Remove(socketPath)
		return nil, fmt.Errorf("vu: chmod %s: %w", socketPath, err)
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
		if s.sess != nil {
			// One frontend at a time: release the previous session's
			// mappings, fds and pump before the new one starts, or two
			// pumps would write the same Backend concurrently.
			s.sess.close()
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
	pumpWg   sync.WaitGroup // tracks the pump goroutine
	// pumpBusy counts pump batches currently in their UNLOCKED Phase 2
	// (dev.process) — their elem SG slices point into the CURRENT mem
	// table's mappings. SET_MEM_TABLE must wait for it to drop to zero
	// before swapping/unmapping (see waitPumpIdleLocked).
	pumpBusy int
	pumpIdle *sync.Cond // signaled when pumpBusy reaches zero (bound to mu)
}

func newSession(dev *BlkDev, c *conn) *session {
	s := &session{dev: dev, c: c}
	s.pumpIdle = sync.NewCond(&s.mu)
	return s
}

// close tears the session down exactly once: it stops the control channel,
// wakes and waits for the pump goroutine, and only then unmaps guest memory
// and closes the eventfds — munmap while the pump still touches v.desc,
// v.avail, v.used or SG slices would be a use-after-munmap (SIGSEGV, not
// recoverable).
func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.pumpWg.Wait() // a concurrent first close is still tearing down
		return
	}
	s.closed = true
	kick := s.vq.kick
	s.mu.Unlock()

	s.c.c.Close() // unblock the control-channel recv
	if kick != nil {
		// Wake the pump so it observes closed and exits. (Closing the fd
		// would NOT interrupt a blocked read(2) on Linux.)
		kick.signal()
	}
	s.pumpWg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
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
		m.closeFds() // release fds no handler took over
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
		// The pump's Phase 2 (dev.process) runs WITHOUT s.mu and touches
		// e.outSG/e.inSG slices into the OLD table's mappings: wait for
		// every in-flight batch to reach Phase 3 BEFORE the swap unmaps
		// those regions — racing it is a use-after-munmap (SIGSEGV).
		s.waitPumpIdleLocked()
		return false, s.mem.setMemTable(m.payload, m.takeFds())

	case reqSetVringNum:
		idx, num := m.vringState()
		if idx != 0 {
			return false, fmt.Errorf("only queue 0 supported (got %d)", idx)
		}
		// virtio requires a power-of-two queue size and pop/push index with
		// % num; reject zero, non-power-of-two and oversized values.
		if num == 0 || num > 32768 || num&(num-1) != 0 {
			return false, fmt.Errorf("vu: invalid vring num %d (want a power of two <= 32768)", num)
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
		s.vq.lastAvail = base & 0xffff // avail idx is 16-bit virtio state
		return false, nil

	case reqGetVringBase:
		// Queue reset: frontend asks for last_avail_idx and stops the queue.
		var p [8]byte
		binary.LittleEndian.PutUint32(p[0:], 0)
		binary.LittleEndian.PutUint32(p[4:], s.vq.lastAvail&0xffff)
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
		// The payload length is peer-controlled; short messages would panic
		// the session goroutine on the Uint32 / [:12] accesses below.
		if len(m.payload) < 12 {
			return false, fmt.Errorf("vu: short GET_CONFIG payload (%d bytes)", len(m.payload))
		}
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
// Takes ownership of the message's fds: the one we adopt is dup'ed, and all
// message fds (including the dup source and any surplus) are closed here so
// reconnects don't leak descriptors.
func (s *session) setVringFile(m *msg, dst **eventfd) error {
	u := m.u64()
	fds := m.takeFds()
	defer closeFds(fds)
	if u&vringNoFD != 0 {
		if *dst != nil {
			(*dst).close()
			*dst = nil
		}
		return nil
	}
	if len(fds) < 1 {
		return errors.New("vu: vring file message without fd")
	}
	fd := fds[0]
	// Dup so our eventfd outlives the message-scoped fd cleanup above.
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
// SET_VRING_KICK so either message order works; pumpOnce dedupes. Callers
// hold s.mu, which also serializes against close(): the closed check keeps
// pumpWg.Add from racing a pumpWg.Wait already in progress.
func (s *session) maybeStartPump() {
	if s.closed || !s.vq.enabled || s.vq.kick == nil {
		return
	}
	s.pumpOnce.Do(func() {
		s.pumpWg.Add(1)
		go func() {
			defer s.pumpWg.Done()
			s.pump()
		}()
	})
}

// waitPumpIdleLocked blocks until no pump batch is in its unlocked Phase
// 2. Caller must hold s.mu; the pump decrements pumpBusy and broadcasts in
// Phase 3 under the same lock, so the wakeup cannot be missed, and Phase 2
// never takes s.mu so it always runs to completion.
func (s *session) waitPumpIdleLocked() {
	for s.pumpBusy > 0 {
		s.pumpIdle.Wait()
	}
}

// pump waits for kicks and drains the avail ring.
//
// Locking: s.mu is only held for the short pop/translateSG and push/notify
// phases. The actual device IO (dev.process, which includes fsync on flush)
// runs WITHOUT the lock, so control-channel messages (handle) and close()
// are never blocked behind a long-running backend request. Guest memory
// slices stay valid while the lock is released because session.close()
// munmaps only after pumpWg.Wait() observes this goroutine finished.
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
		for {
			// Phase 1 (locked): pop a bounded batch of requests and resolve
			// their descriptor chains into guest-memory SG slices.
			batch := s.popBatch()
			if len(batch) == 0 {
				break
			}
			// Phase 2 (unlocked): pure device IO — read/write/fsync.
			type result struct {
				e       *elem
				usedLen uint32
			}
			results := make([]result, 0, len(batch))
			for _, e := range batch {
				usedLen, err := s.dev.process(e)
				if err != nil {
					log.Printf("vu: blk request: %v", err)
					continue
				}
				results = append(results, result{e: e, usedLen: usedLen})
			}
			// Phase 3 (locked): publish completions and interrupt the guest.
			s.mu.Lock()
			s.pumpBusy-- // batch left Phase 2; wake any SET_MEM_TABLE waiter
			s.pumpIdle.Broadcast()
			if s.closed {
				s.mu.Unlock()
				return
			}
			for _, r := range results {
				if err := s.vq.push(r.e, r.usedLen); err != nil {
					log.Printf("vu: push: %v", err)
					break
				}
			}
			if err := s.vq.notify(); err != nil {
				log.Printf("vu: notify: %v", err)
			}
			s.mu.Unlock()
			// A full batch means more work may be pending; otherwise the
			// queue is drained and we go back to waiting for a kick.
			if len(batch) < pumpMaxBatch {
				break
			}
		}
	}
}

// pumpMaxBatch bounds how many requests one locked pop phase extracts
// before releasing s.mu for the (potentially slow) device IO.
const pumpMaxBatch = 128

// popBatch pops up to pumpMaxBatch elements under s.mu. It returns early
// (empty batch) when the session is closed or the queue errors out. A
// non-empty batch marks the pump busy (its Phase 2 runs unlocked right
// after) so a concurrent SET_MEM_TABLE waits instead of unmapping the
// memory those elements' SG slices point into.
func (s *session) popBatch() []*elem {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	batch := make([]*elem, 0, pumpMaxBatch)
	for len(batch) < pumpMaxBatch {
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
		batch = append(batch, e)
	}
	if len(batch) > 0 {
		// Batch enters Phase 2 (unlocked) the moment this returns; the
		// increment happens under the SAME lock hold as the pops, so a
		// SET_MEM_TABLE that acquires s.mu afterwards necessarily sees
		// pumpBusy > 0 and waits.
		s.pumpBusy++
	}
	return batch
}
