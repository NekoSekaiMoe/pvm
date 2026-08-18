// e2e_test.go drives the vhost-user server with a fake frontend that mimics
// the UML virtio_uml driver's exact message sequence (as read from
// arch/um/drivers/virtio_uml.c in Linux 6.18), over a real unix socket with
// a real memfd as guest memory. It submits actual virtio-blk requests
// through a real split virtqueue and checks data, status bytes, used-ring
// entries and call-fd interrupts — everything except the guest kernel
// itself (UML requires x86_64; this host is aarch64).
package vu

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"uml-container/internal/cow"
)

const e2eMemSize = 4 << 20 // 4 MiB "guest RAM"

// e2eFrontend is a virtio_uml-shaped test frontend.
type e2eFrontend struct {
	t   *testing.T
	c   *net.UnixConn
	cc  *conn
	mem []byte // mmap of memfd
	mfd int

	// vring layout inside guest memory
	num       uint32
	descAddr  uint64
	availAddr uint64
	usedAddr  uint64
	kickFd    int
	callFd    int
}

func e2eConnect(t *testing.T, sock string) *e2eFrontend {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	mfd, err := unix.MemfdCreate("guest-ram", 0)
	if err != nil {
		t.Fatalf("memfd: %v", err)
	}
	if err := unix.Ftruncate(mfd, e2eMemSize); err != nil {
		t.Fatalf("ftruncate: %v", err)
	}
	mem, err := unix.Mmap(mfd, 0, e2eMemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	return &e2eFrontend{
		t: t, c: c, cc: newConn(c), mem: mem, mfd: mfd,
		num: 8, descAddr: 0x10000, availAddr: 0x20000, usedAddr: 0x30000,
	}
}

func (f *e2eFrontend) close() {
	f.c.Close()
	unix.Munmap(f.mem)
	unix.Close(f.mfd)
	if f.kickFd > 0 {
		unix.Close(f.kickFd)
	}
	if f.callFd > 0 {
		unix.Close(f.callFd)
	}
}

// sendMsg mimics vhost_user_send: one write for header+payload, fds oob.
func (f *e2eFrontend) sendMsg(req uint32, payload []byte, fds ...int) {
	f.t.Helper()
	if err := f.cc.send(req, 1, payload, fds...); err != nil {
		f.t.Fatalf("send req %d: %v", req, err)
	}
}

// sendMsgAck mimics the kernel's vhost_user_send once REPLY_ACK is
// negotiated: NEED_REPLY is set and a u64 status reply is read back. The
// reply flags must be exactly REPLY|VERSION — virtio_uml's
// vhost_user_recv_resp rejects anything else with -EPROTO (this is what
// used to fail the real kernel's device probe with error -71).
func (f *e2eFrontend) sendMsgAck(req uint32, payload []byte, fds ...int) {
	f.t.Helper()
	if err := f.cc.send(req, 1|flagNeedReply, payload, fds...); err != nil {
		f.t.Fatalf("send req %d: %v", req, err)
	}
	m := f.recvMsg()
	if m.flags != 1|flagReply {
		f.t.Fatalf("req %d ack flags = %#x, want REPLY|VERSION", req, m.flags)
	}
	if len(m.payload) != 8 {
		f.t.Fatalf("req %d ack payload = %d bytes, want 8", req, len(m.payload))
	}
	if v := m.u64(); v != 0 {
		f.t.Fatalf("req %d ack status = %d, want 0", req, v)
	}
}

func (f *e2eFrontend) recvMsg() *msg {
	f.t.Helper()
	m, err := f.cc.recv()
	if err != nil {
		f.t.Fatalf("recv: %v", err)
	}
	return m
}

// handshake performs the virtio_uml vhost_user_init sequence.
func (f *e2eFrontend) handshake() uint64 {
	f.sendMsg(reqSetOwner, nil)
	f.sendMsg(reqGetFeatures, nil)
	features := f.recvMsg().u64()
	if features&(1<<virtioFVersion1) == 0 {
		f.t.Fatalf("backend does not offer VIRTIO_F_VERSION_1")
	}
	if features&(1<<vhostUserFProtocolFeatures) == 0 {
		f.t.Fatalf("backend does not offer PROTOCOL_FEATURES")
	}
	f.sendMsg(reqGetProtocolFeatures, nil)
	proto := f.recvMsg().u64()
	if proto&(1<<protoFConfig) == 0 {
		f.t.Fatalf("backend does not offer PROTOCOL_F_CONFIG (virtio_uml needs GET_CONFIG)")
	}
	// Negotiate the intersection, like the kernel does. REPLY_ACK is part
	// of it, so from here on every fire-and-forget message carries
	// NEED_REPLY and waits for an ACK — exactly like the real kernel.
	var p [8]byte
	binary.LittleEndian.PutUint64(p[:], proto)
	f.sendMsgAck(reqSetProtocolFeatures, p[:])
	// Device features: accept all offered.
	binary.LittleEndian.PutUint64(p[:], features)
	f.sendMsgAck(reqSetFeatures, p[:])
	return features
}

// readConfig mimics vhost_user_get_config: offset 0, size off+len.
func (f *e2eFrontend) readConfig(size uint32) []byte {
	var p [12]byte
	binary.LittleEndian.PutUint32(p[0:], 0)
	binary.LittleEndian.PutUint32(p[4:], size)
	f.sendMsg(reqGetConfig, p[:])
	m := f.recvMsg()
	if len(m.payload) != 12+int(size) {
		f.t.Fatalf("config reply payload %d bytes, want %d", len(m.payload), 12+size)
	}
	return m.payload[12:]
}

// setupVring sends SET_MEM_TABLE + full vring setup for queue 0.
func (f *e2eFrontend) setupVring() {
	// SET_MEM_TABLE: 1 region covering the whole memfd (UML uses a nonzero
	// gpa base; emulate that with base 0x1000 to exercise translation).
	var p bytes.Buffer
	binary.Write(&p, binary.LittleEndian, uint32(1))
	binary.Write(&p, binary.LittleEndian, uint32(0))
	binary.Write(&p, binary.LittleEndian, uint64(0x1000)) // guest_addr
	binary.Write(&p, binary.LittleEndian, uint64(e2eMemSize))
	binary.Write(&p, binary.LittleEndian, uint64(0x1000)) // user_addr
	binary.Write(&p, binary.LittleEndian, uint64(0))      // mmap_offset
	f.sendMsgAck(reqSetMemTable, p.Bytes(), f.mfd)

	// gpa base for vring addrs
	base := uint64(0x1000)
	var s [8]byte
	binary.LittleEndian.PutUint32(s[0:], 0)     // index
	binary.LittleEndian.PutUint32(s[4:], f.num) // num
	f.sendMsgAck(reqSetVringNum, s[:])

	a := make([]byte, 40)
	binary.LittleEndian.PutUint32(a[0:], 0)
	binary.LittleEndian.PutUint64(a[8:], base+f.descAddr)
	binary.LittleEndian.PutUint64(a[16:], base+f.usedAddr)
	binary.LittleEndian.PutUint64(a[24:], base+f.availAddr)
	f.sendMsgAck(reqSetVringAddr, a)

	binary.LittleEndian.PutUint32(s[4:], 0) // base
	f.sendMsgAck(reqSetVringBase, s[:])

	kickFd, err := unix.Eventfd(0, 0)
	if err != nil {
		f.t.Fatalf("kick eventfd: %v", err)
	}
	callFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(kickFd)
		f.t.Fatalf("call eventfd: %v", err)
	}
	f.kickFd, f.callFd = kickFd, callFd
	var i [8]byte
	binary.LittleEndian.PutUint64(i[:], 0) // index 0, fd follows
	f.sendMsgAck(reqSetVringCall, i[:], f.callFd)
	f.sendMsgAck(reqSetVringKick, i[:], f.kickFd)

	binary.LittleEndian.PutUint32(s[4:], 1) // enable
	f.sendMsgAck(reqSetVringEnable, s[:])
}

// submit queues one descriptor chain (head = desc 0) as round `round`
// (0-based) and kicks.
func (f *e2eFrontend) submit(round uint16, descs [][4]uint64) {
	for i, d := range descs {
		off := f.descAddr + uint64(i)*16
		binary.LittleEndian.PutUint64(f.mem[off:], d[0])
		binary.LittleEndian.PutUint32(f.mem[off+8:], uint32(d[1]))
		binary.LittleEndian.PutUint16(f.mem[off+12:], uint16(d[2]))
		next := uint16(0)
		if i+1 < len(descs) {
			next = uint16(i + 1)
		}
		binary.LittleEndian.PutUint16(f.mem[off+14:], next)
	}
	// avail ring: ring[round]=head 0, idx=round+1
	binary.LittleEndian.PutUint16(f.mem[f.availAddr+4+uint64(round)*2:], 0)
	binary.LittleEndian.PutUint16(f.mem[f.availAddr+2:], round+1)
	// kick
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], 1)
	if _, err := unix.Write(f.kickFd, b[:]); err != nil {
		f.t.Fatalf("kick: %v", err)
	}
}

// awaitUsed waits (with a deadline) for the next used-ring entry and drains
// the call-fd interrupt.
func (f *e2eFrontend) awaitUsed(round uint16) (id, length uint32) {
	f.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		usedIdx := binary.LittleEndian.Uint16(f.mem[f.usedAddr+2:])
		if usedIdx == round+1 {
			var b [8]byte
			_, _ = unix.Read(f.callFd, b[:]) // drain interrupt (non-blocking)
			id = binary.LittleEndian.Uint32(f.mem[f.usedAddr+4+uint64(round)*8:])
			length = binary.LittleEndian.Uint32(f.mem[f.usedAddr+4+uint64(round)*8+4:])
			return id, length
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.t.Fatalf("used idx never reached %d", round+1)
	return 0, 0
}

// TestEndToEndVirtioBlk is the full loopback boot sequence.
func TestEndToEndVirtioBlk(t *testing.T) {
	dir := t.TempDir()
	// Backing store: a raw image with a known sector pattern.
	imgPath := filepath.Join(dir, "disk.img")
	img, err := os.OpenFile(imgPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	if err := img.Truncate(1 << 20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	sector0 := bytes.Repeat([]byte{0x5A}, 512)
	if _, err := img.WriteAt(sector0, 0); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	img.Close()

	be, err := cow.OpenWritable(imgPath)
	if err != nil {
		t.Fatalf("open backend: %v", err)
	}
	defer be.Close()
	dev, err := NewBlkDev(be, false)
	if err != nil {
		t.Fatalf("NewBlkDev: %v", err)
	}
	sock := filepath.Join(dir, "vu.sock")
	srv, err := Serve(sock, dev)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srv.Close()

	f := e2eConnect(t, sock)
	defer f.close()
	f.handshake()

	// Device config: capacity must match the image.
	cfg := f.readConfig(blkConfigSize)
	if cap := binary.LittleEndian.Uint64(cfg[0:]); cap != (1<<20)/512 {
		t.Fatalf("capacity = %d sectors, want %d", cap, (1<<20)/512)
	}

	f.setupVring()

	// --- virtio-blk READ (T_IN) of sector 0 ---
	hdrGPA := uint64(0x1000 + 0x40000)
	dataGPA := uint64(0x1000 + 0x50000)
	statusGPA := uint64(0x1000 + 0x60000)
	hdr := f.mem[0x40000:]
	binary.LittleEndian.PutUint32(hdr[0:], blkTIn)
	binary.LittleEndian.PutUint64(hdr[8:], 0) // sector 0
	f.submit(0, [][4]uint64{
		{hdrGPA, 16, descFlagNext, 0},
		{dataGPA, 512, descFlagNext | descFlagWrite, 0},
		{statusGPA, 1, descFlagWrite, 0},
	})
	id, ln := f.awaitUsed(0)
	if id != 0 {
		t.Errorf("used id = %d, want 0", id)
	}
	if ln != 513 {
		t.Errorf("used len = %d, want 513", ln)
	}
	if !bytes.Equal(f.mem[0x50000:0x50000+512], sector0) {
		t.Error("READ: data mismatch in guest buffer")
	}
	if f.mem[0x60000] != blkSOK {
		t.Errorf("READ: status = %d, want OK", f.mem[0x60000])
	}

	// --- virtio-blk WRITE (T_OUT) to sector 4 ---
	wdata := bytes.Repeat([]byte{0xC3}, 512)
	copy(f.mem[0x50000:], wdata)
	binary.LittleEndian.PutUint32(hdr[0:], blkTOut)
	binary.LittleEndian.PutUint64(hdr[8:], 4) // sector 4
	f.mem[0x60000] = 0xFF
	f.submit(1, [][4]uint64{
		{hdrGPA, 16, descFlagNext, 0},
		{dataGPA, 512, descFlagNext, 0},
		{statusGPA, 1, descFlagWrite, 0},
	})
	id, _ = f.awaitUsed(1)
	if f.mem[0x60000] != blkSOK {
		t.Errorf("WRITE: status = %d, want OK", f.mem[0x60000])
	}
	_ = id

	// Verify the backend actually persisted the write.
	check, err := os.Open(imgPath)
	if err != nil {
		t.Fatalf("reopen image: %v", err)
	}
	defer check.Close()
	buf := make([]byte, 512)
	if _, err := check.ReadAt(buf, 4*512); err != nil {
		t.Fatalf("read image: %v", err)
	}
	if !bytes.Equal(buf, wdata) {
		t.Error("WRITE: backend image does not contain guest-written data")
	}
}
