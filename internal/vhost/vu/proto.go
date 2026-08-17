// Package vu implements a minimal vhost-user backend (server) sufficient to
// boot a UML guest's virtio_uml driver with a virtio-blk device — replacing
// the qemu-storage-daemon subprocess for the CoW/vhost path.
//
// Scope: vhost-user over a unix socket, one queue, split virtqueues (with
// indirect descriptors), memory table via SCM_RIGHTS + mmap, virtio-blk
// IN/OUT/FLUSH/GET_ID requests. No migration, no MQ, no packed rings, no
// INFLIGHT — none of those are used by the UML frontend.
//
// Protocol reference: qemu docs/interop/vhost-user.rst and
// subprojects/libvhost-user/libvhost-user.h (wire structs mirrored here).
package vu

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Vhost-user request codes (VhostUserRequest in libvhost-user.h).
const (
	reqGetFeatures         = 1
	reqSetFeatures         = 2
	reqSetOwner            = 3
	reqResetOwner          = 4
	reqSetMemTable         = 5
	reqSetLogBase          = 6
	reqSetLogFd            = 7
	reqSetVringNum         = 8
	reqSetVringAddr        = 9
	reqSetVringBase        = 10
	reqGetVringBase        = 11
	reqSetVringKick        = 12
	reqSetVringCall        = 13
	reqSetVringErr         = 14
	reqGetProtocolFeatures = 15
	reqSetProtocolFeatures = 16
	reqGetQueueNum         = 17
	reqSetVringEnable      = 18
	reqSetVringEndian      = 23
	reqGetConfig           = 24
	reqSetConfig           = 25
	reqGetStatus           = 39
	reqSetStatus           = 40
	reqGetSharedObject     = 41
)

// Message header flag bits (VhostUserMsg.flags).
const (
	flagVersion   = 0x3 // protocol version, must be 1
	flagReply     = 0x4 // message is a reply
	flagNeedReply = 0x8 // frontend wants an explicit ack
)

// Vring file payload bits: low 8 bits queue index, bit 8 = no fd passed.
const vringNoFD = 0x100

// Device-level feature bits we advertise (virtio_blk.h + virtio ring).
const (
	virtioBlkFSizeMax = 1
	virtioBlkFSegMax  = 2
	virtioBlkFBlkSize = 6
	virtioBlkFFlush   = 9
	virtioBlkFRo      = 5

	virtioFVersion1 = 32

	vhostUserFProtocolFeatures = 30
)

// vhost-user protocol features (VhostUserProtocolFeatures).
const (
	protoFReplyAck = 3
	protoFConfig   = 9
	protoFStatus   = 16
)

// ourProtocolFeatures is what we can do: device config over the control
// channel (virtio_uml has no PCI config space, it MUST use GET_CONFIG) and
// explicit reply-ack.
const ourProtocolFeatures = (1 << protoFConfig) | (1 << protoFReplyAck)

// msg is a decoded vhost-user message.
type msg struct {
	request uint32
	flags   uint32
	payload []byte
	fds     []int
}

func (m *msg) u64() uint64 {
	if len(m.payload) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(m.payload)
}

// vringState mirrors struct vhost_vring_state { u32 index; u32 num }.
func (m *msg) vringState() (index, num uint32) {
	if len(m.payload) < 8 {
		return 0, 0
	}
	return binary.LittleEndian.Uint32(m.payload), binary.LittleEndian.Uint32(m.payload[4:])
}

// vringAddr mirrors struct vhost_vring_addr (uapi/linux/vhost.h):
// u32 index; u32 flags; u64 desc; u64 used; u64 avail; u64 log.
type vringAddr struct {
	index uint32
	flags uint32
	desc  uint64
	used  uint64
	avail uint64
	log   uint64
}

func (m *msg) vringAddr() vringAddr {
	var a vringAddr
	p := m.payload
	if len(p) < 40 {
		return a
	}
	a.index = binary.LittleEndian.Uint32(p[0:])
	a.flags = binary.LittleEndian.Uint32(p[4:])
	a.desc = binary.LittleEndian.Uint64(p[8:])
	a.used = binary.LittleEndian.Uint64(p[16:])
	a.avail = binary.LittleEndian.Uint64(p[24:])
	a.log = binary.LittleEndian.Uint64(p[32:])
	return a
}

// conn wraps the control socket with fd-passing read/write of whole
// vhost-user messages.
type conn struct {
	c *net.UnixConn
}

func newConn(c *net.UnixConn) *conn { return &conn{c: c} }

// recv reads one message. Payload is capped defensively: the largest
// legitimate payload is the memory table (nregions*32 + 8 with the baseline
// 8 regions == 264) or a config read (4096+12).
func (c *conn) recv() (*msg, error) {
	// The socket is SOCK_STREAM, so one read may coalesce multiple messages:
	// read exactly the 12-byte header first (fds arrive attached to the first
	// bytes of a sendmsg batch), then exactly `size` payload bytes.
	hdr := make([]byte, 0, 12)
	oob := make([]byte, unix.CmsgSpace(4*8)) // up to 8 fds
	var fds []int
	for len(hdr) < 12 {
		chunk := make([]byte, 12-len(hdr))
		n, oobn, _, _, err := c.c.ReadMsgUnix(chunk, oob)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.EOF
		}
		hdr = append(hdr, chunk[:n]...)
		if oobn > 0 {
			cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
			if err == nil {
				for _, cmsg := range cmsgs {
					if got, err := unix.ParseUnixRights(&cmsg); err == nil {
						fds = append(fds, got...)
					}
				}
			}
		}
	}
	m := &msg{
		request: binary.LittleEndian.Uint32(hdr[0:]),
		flags:   binary.LittleEndian.Uint32(hdr[4:]),
		fds:     fds,
	}
	size := binary.LittleEndian.Uint32(hdr[8:])
	if size > 8192 {
		return nil, fmt.Errorf("vu: implausible payload size %d", size)
	}
	if size > 0 {
		m.payload = make([]byte, size)
		if _, err := io.ReadFull(c.c, m.payload); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// reply sends a response to m with the given payload and optional fds.
func (c *conn) reply(m *msg, payload []byte, fds ...int) error {
	return c.send(m.request, m.flags|flagReply, payload, fds...)
}

// ack replies to a NEED_REPLY message with a u64 zero ("success").
func (c *conn) ack(m *msg) error {
	return c.reply(m, make([]byte, 8))
}

func (c *conn) send(request, flags uint32, payload []byte, fds ...int) error {
	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint32(hdr[0:], request)
	binary.LittleEndian.PutUint32(hdr[4:], (flags&^flagVersion)|1) // version 1
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(payload)))
	buf := append(hdr, payload...)
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	_, _, err := c.c.WriteMsgUnix(buf, oob, nil)
	return err
}

// eventfd wraps a Linux eventfd passed over the control channel.
type eventfd struct{ f *os.File }

func (e *eventfd) close() {
	if e.f != nil {
		e.f.Close()
	}
}

// wait blocks until the frontend kicks (eventfd counter becomes non-zero),
// then drains it.
func (e *eventfd) wait() error {
	var b [8]byte
	for {
		_, err := e.f.Read(b[:])
		if err == unix.EINTR {
			continue
		}
		return err
	}
}

// signal bumps the eventfd (used for call/irq towards the guest).
func (e *eventfd) signal() error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], 1)
	_, err := e.f.Write(b[:])
	return err
}
