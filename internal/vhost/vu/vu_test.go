package vu

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeGuest builds a synthetic guest memory (single region, gpa 0) with a
// vring laid out at the given addresses.
type fakeGuest struct {
	mt    *memTable
	mem   []byte
	num   uint32
	desc  uint64
	avail uint64
	used  uint64
}

func newFakeGuest(size int, num uint32) *fakeGuest {
	mem := make([]byte, size)
	g := &fakeGuest{
		mt:    &memTable{regions: []memRegion{{gpa: 0, size: uint64(size), data: mem, fd: -1}}},
		mem:   mem,
		num:   num,
		desc:  0x1000,
		avail: 0x2000,
		used:  0x3000,
	}
	return g
}

func (g *fakeGuest) putDesc(idx uint32, addr uint64, length uint32, flags uint16, next uint16) {
	d := g.mem[g.desc+uint64(idx)*16:]
	binary.LittleEndian.PutUint64(d[0:], addr)
	binary.LittleEndian.PutUint32(d[8:], length)
	binary.LittleEndian.PutUint16(d[12:], flags)
	binary.LittleEndian.PutUint16(d[14:], next)
}

func (g *fakeGuest) setAvailIdx(idx uint16) {
	binary.LittleEndian.PutUint16(g.mem[g.avail+2:], idx)
}

func (g *fakeGuest) setAvailRing(slot uint16, head uint16) {
	binary.LittleEndian.PutUint16(g.mem[g.avail+4+uint64(slot)*2:], head)
}

func (g *fakeGuest) vring(t *testing.T) *vring {
	t.Helper()
	v := &vring{num: g.num}
	if err := v.setup(g.mt, vringAddr{desc: g.desc, used: g.used, avail: g.avail}); err != nil {
		t.Fatalf("vring setup: %v", err)
	}
	return v
}

// memBackend is an in-memory Backend for device tests.
type memBackend struct{ data []byte }

func (m *memBackend) ReadAt(p []byte, off int64) (int, error) {
	return bytes.NewReader(m.data).ReadAt(p, off)
}
func (m *memBackend) WriteAt(p []byte, off int64) (int, error) {
	copy(m.data[off:], p)
	return len(p), nil
}
func (m *memBackend) Sync() error  { return nil }
func (m *memBackend) Size() int64  { return int64(len(m.data)) }
func (m *memBackend) Close() error { return nil }

// TestVringPopDirectChain: a 3-descriptor chain (out hdr, out data, in status).
func TestVringPopDirectChain(t *testing.T) {
	g := newFakeGuest(1<<20, 8)
	g.putDesc(0, 0x4000, 16, descFlagNext, 1)  // out hdr
	g.putDesc(1, 0x5000, 512, descFlagNext, 2) // out data
	g.putDesc(2, 0x6000, 1, descFlagWrite, 0)  // in status
	g.setAvailRing(0, 0)
	g.setAvailIdx(1)

	v := g.vring(t)
	e, err := v.pop(g.mt)
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	if e == nil {
		t.Fatal("pop returned nil with available descriptor")
	}
	if err := e.translateSG(g.mt); err != nil {
		t.Fatalf("translate: %v", err)
	}
	if e.head != 0 {
		t.Errorf("head = %d, want 0", e.head)
	}
	if len(e.outSG) != 2 || len(e.inSG) != 1 {
		t.Fatalf("sg split: out=%d in=%d, want 2/1", len(e.outSG), len(e.inSG))
	}
	if &e.outSG[0][0] != &g.mem[0x4000] {
		t.Error("out hdr slice points at wrong guest memory")
	}
	// second pop: queue empty
	if e2, _ := v.pop(g.mt); e2 != nil {
		t.Error("pop should return nil when avail is drained")
	}
}

// TestVringPopIndirect: indirect descriptor table expansion.
func TestVringPopIndirect(t *testing.T) {
	g := newFakeGuest(1<<20, 8)
	// indirect table at 0x7000 with 2 entries: out hdr, in data
	it := 0x7000
	binary.LittleEndian.PutUint64(g.mem[it:], 0x4000)
	binary.LittleEndian.PutUint32(g.mem[it+8:], 16)
	binary.LittleEndian.PutUint16(g.mem[it+12:], descFlagNext)
	binary.LittleEndian.PutUint64(g.mem[it+16:], 0x5000)
	binary.LittleEndian.PutUint32(g.mem[it+24:], 512)
	binary.LittleEndian.PutUint16(g.mem[it+28:], descFlagWrite)

	g.putDesc(3, uint64(it), 32, descFlagIndirect, 0)
	g.setAvailRing(0, 3)
	g.setAvailIdx(1)

	v := g.vring(t)
	e, err := v.pop(g.mt)
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	if e == nil {
		t.Fatal("pop nil")
	}
	if err := e.translateSG(g.mt); err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(e.outSG) != 1 || len(e.inSG) != 1 {
		t.Fatalf("indirect sg split: out=%d in=%d, want 1/1", len(e.outSG), len(e.inSG))
	}
	if len(e.inSG[0]) != 512 {
		t.Errorf("in sg len = %d, want 512", len(e.inSG[0]))
	}
}

// TestVringPushNotify: used ring update + interrupt unless masked.
// TestReplyClearsNeedReply is a regression test for the virtio_uml probe
// failure (error -71): once REPLY_ACK is negotiated the kernel sends every
// fire-and-forget message with NEED_REPLY and rejects any reply whose flags
// are not exactly REPLY|VERSION. Echoing NEED_REPLY back breaks the probe.
func TestReplyClearsNeedReply(t *testing.T) {
	cases := []struct {
		name  string
		flags uint32 // request flags the frontend sends
	}{
		{"request with NEED_REPLY (post REPLY_ACK negotiation)", 1 | flagNeedReply},
		{"plain request", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatalf("socketpair: %v", err)
			}
			toConn := func(fd int) *conn {
				f := os.NewFile(uintptr(fd), "sock")
				defer f.Close() // FileConn dup'ed the fd; the original is done
				uc, err := net.FileConn(f)
				if err != nil {
					t.Fatalf("FileConn: %v", err)
				}
				return newConn(uc.(*net.UnixConn))
			}
			server, client := toConn(fds[0]), toConn(fds[1])
			// The conns own the (dup'ed) descriptors; closing them releases
			// everything. Do NOT unix.Close the socketpair fds — they were
			// already closed inside toConn and the numbers may be reused.
			defer server.c.Close()
			defer client.c.Close()

			// Frontend sends a request, backend ACKs it.
			if err := client.send(reqSetVringEnable, tc.flags, make([]byte, 8)); err != nil {
				t.Fatalf("send: %v", err)
			}
			m, err := server.recv()
			if err != nil {
				t.Fatalf("recv: %v", err)
			}
			if err := server.ack(m); err != nil {
				t.Fatalf("ack: %v", err)
			}
			resp, err := client.recv()
			if err != nil {
				t.Fatalf("recv resp: %v", err)
			}
			const want = 1 | flagReply // REPLY|VERSION, NEED_REPLY cleared
			if resp.flags != want {
				t.Fatalf("reply flags = %#x, want %#x", resp.flags, want)
			}
		})
	}
}

func TestVringPushNotify(t *testing.T) {
	g := newFakeGuest(1<<20, 8)
	callFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatalf("eventfd: %v", err)
	}
	// os.NewFile takes ownership of the fd; closing is left to the
	// resulting *os.File (a separate unix.Close would double-close).
	v := g.vring(t)
	v.call = &eventfd{f: os.NewFile(uintptr(callFd), "call")}

	e := &elem{head: 5}
	if err := v.push(e, 42); err != nil {
		t.Fatalf("push: %v", err)
	}
	id := binary.LittleEndian.Uint32(g.mem[g.used+4:])
	ln := binary.LittleEndian.Uint32(g.mem[g.used+8:])
	idx := binary.LittleEndian.Uint16(g.mem[g.used+2:])
	if id != 5 || ln != 42 || idx != 1 {
		t.Errorf("used ring: id=%d len=%d idx=%d, want 5/42/1", id, ln, idx)
	}
	if err := v.notify(); err != nil {
		t.Fatalf("notify: %v", err)
	}
	var b [8]byte
	if _, err := unix.Read(callFd, b[:]); err != nil {
		t.Fatalf("expected interrupt on call fd: %v", err)
	}

	// Mask interrupts: no signal.
	binary.LittleEndian.PutUint16(g.mem[g.avail:], vringAvailFNoInterrupt)
	if err := v.notify(); err != nil {
		t.Fatalf("notify masked: %v", err)
	}
	if _, err := unix.Read(callFd, b[:]); err == nil {
		t.Error("interrupt delivered despite NO_INTERRUPT")
	}
}

// TestBlkProcess: IN/OUT/FLUSH/GET_ID/unknown against a memory backend.
func TestBlkProcess(t *testing.T) {
	be := &memBackend{data: make([]byte, 1<<20)}
	be.WriteAt(bytes.Repeat([]byte{0xAB}, 512), 0) // sector 0
	dev, err := NewBlkDev(be, false)
	if err != nil {
		t.Fatalf("NewBlkDev: %v", err)
	}

	mkElem := func(typ uint32, sector uint64, dataOut []byte, inSize int) *elem {
		hdr := make([]byte, 16)
		binary.LittleEndian.PutUint32(hdr[0:], typ)
		binary.LittleEndian.PutUint64(hdr[8:], sector)
		e := &elem{head: 0}
		e.outSG = [][]byte{hdr}
		if dataOut != nil {
			e.outSG = append(e.outSG, dataOut)
		}
		e.inSG = [][]byte{make([]byte, inSize), make([]byte, 1)}
		return e
	}

	// IN: read sector 0
	e := mkElem(blkTIn, 0, nil, 512)
	used, err := dev.process(e)
	if err != nil {
		t.Fatalf("IN: %v", err)
	}
	if used != 513 || e.inSG[0][0] != 0xAB || e.inSG[1][0] != blkSOK {
		t.Errorf("IN: used=%d data=%#x status=%d", used, e.inSG[0][0], e.inSG[1][0])
	}

	// OUT: write sector 2
	payload := bytes.Repeat([]byte{0xCD}, 512)
	e = mkElem(blkTOut, 2, payload, 0)
	if _, err := dev.process(e); err != nil {
		t.Fatalf("OUT: %v", err)
	}
	if e.inSG[1][0] != blkSOK || be.data[2*512] != 0xCD {
		t.Errorf("OUT: status=%d data=%#x", e.inSG[1][0], be.data[2*512])
	}

	// FLUSH
	e = mkElem(blkTFlush, 0, nil, 0)
	if _, err := dev.process(e); err != nil || e.inSG[1][0] != blkSOK {
		t.Errorf("FLUSH: %v status=%d", err, e.inSG[1][0])
	}

	// GET_ID
	e = mkElem(blkTGetID, 0, nil, 64)
	if _, err := dev.process(e); err != nil || string(e.inSG[0][:3]) != "pvm" {
		t.Errorf("GET_ID: %v id=%q", err, e.inSG[0])
	}

	// unknown type
	e = mkElem(77, 0, nil, 0)
	if _, err := dev.process(e); err != nil || e.inSG[1][0] != blkSUnsupp {
		t.Errorf("unknown: %v status=%d, want UNSUPP", err, e.inSG[1][0])
	}

	// read-only device rejects writes
	ro, _ := NewBlkDev(be, true)
	e = mkElem(blkTOut, 0, payload, 0)
	if _, err := ro.process(e); err != nil || e.inSG[1][0] != blkSIOErr {
		t.Errorf("ro OUT: %v status=%d, want IOERR", err, e.inSG[1][0])
	}
}

// TestServerHandshake: real socket, fake frontend, feature negotiation +
// config read.
func TestServerHandshake(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "vu.sock")
	be := &memBackend{data: make([]byte, 1<<20)}
	dev, err := NewBlkDev(be, false)
	if err != nil {
		t.Fatalf("NewBlkDev: %v", err)
	}
	srv, err := Serve(sock, dev)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srv.Close()

	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	fc := newConn(c)

	send := func(req uint32, payload []byte) *msg {
		t.Helper()
		if err := fc.send(req, 1, payload); err != nil {
			t.Fatalf("send req %d: %v", req, err)
		}
		m, err := fc.recv()
		if err != nil {
			t.Fatalf("recv reply for %d: %v", req, err)
		}
		return m
	}

	// GET_FEATURES
	m := send(reqGetFeatures, nil)
	feat := m.u64()
	if feat&(1<<virtioFVersion1) == 0 || feat&(1<<vhostUserFProtocolFeatures) == 0 {
		t.Errorf("features %#x missing VERSION_1/PROTOCOL_FEATURES", feat)
	}
	// GET_PROTOCOL_FEATURES
	m = send(reqGetProtocolFeatures, nil)
	if m.u64() != ourProtocolFeatures {
		t.Errorf("protocol features = %#x, want %#x", m.u64(), ourProtocolFeatures)
	}
	// SET_PROTOCOL_FEATURES: enable reply-ack
	var p [8]byte
	binary.LittleEndian.PutUint64(p[:], ourProtocolFeatures)
	if err := fc.send(reqSetProtocolFeatures, 1, p[:]); err != nil {
		t.Fatalf("set proto: %v", err)
	}
	// SET_FEATURES with NEED_REPLY must get an ack now
	if err := fc.send(reqSetFeatures, 1|flagNeedReply, p[:]); err != nil {
		t.Fatalf("set features: %v", err)
	}
	ack, err := fc.recv()
	if err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	if ack.request != reqSetFeatures || ack.u64() != 0 {
		t.Errorf("ack: req=%d val=%d", ack.request, ack.u64())
	}
	// GET_CONFIG
	cp := make([]byte, 12) // offset 0, size 4, flags 0
	binary.LittleEndian.PutUint32(cp[4:], 8)
	m = send(reqGetConfig, cp)
	if len(m.payload) != 20 {
		t.Fatalf("config reply payload = %d bytes, want 20", len(m.payload))
	}
	capSectors := binary.LittleEndian.Uint64(m.payload[12:])
	if capSectors != (1<<20)/512 {
		t.Errorf("capacity = %d sectors, want %d", capSectors, (1<<20)/512)
	}
}
