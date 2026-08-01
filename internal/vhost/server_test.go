package vhost

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"uml-container/internal/state"
)

// These tests drive the vhost-user protocol over a real Unix socket pair,
// validating the review.md fixes without needing a running UML kernel:
//   - protocol feature bits (#1)
//   - getQueue upper bound / nil handling (#10)
//   - SET_VRING_NUM validation (#2)
//   - GET_VRING_BASE 8-byte reply layout (#3)
//   - REPLY_ACK u64 payload (#8)
//   - GET_CONFIG offset/size slicing (#9)
//   - SET_VRING_CALL/KICK fd replacement / no duplicate processors (#4)

// startTestServer wires a Server with a fake block device backed by a temp
// file, listens on a temp socket, and returns the server plus a dialed conn
// pair (client, srvConn). The server's handleConn is run on srvConn so the
// test can speak vhost-user from the client side.
func startTestServer(t *testing.T, sizeBytes int64) (*Server, *BlockDevice, net.Conn) {
	t.Helper()
	root := t.TempDir()
	orig := state.RootDir
	state.RootDir = root
	t.Cleanup(func() { state.RootDir = orig })

	imgPath := filepath.Join(root, "disk.img")
	f, err := os.OpenFile(imgPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("create img: %v", err)
	}
	if err := f.Truncate(sizeBytes); err != nil {
		f.Close()
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	blk, err := NewBlockDevice(imgPath)
	if err != nil {
		t.Fatalf("NewBlockDevice: %v", err)
	}
	t.Cleanup(func() {
		if err := blk.Close(); err != nil {
			t.Logf("blk.Close: %v", err)
		}
	})

	sockPath := filepath.Join(root, "vhost.sock")
	srv := NewServer(sockPath, blk, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(srv.Stop)

	// Dial the server; its acceptLoop accepts and runs handleConn.
	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	return srv, blk, client
}

// send writes a vhost-user request without waiting for a reply.
func send(t *testing.T, c net.Conn, request uint32, needReply bool, payload []byte) {
	t.Helper()
	hdr := VhostUserMsgHeader{Request: request, Size: uint32(len(payload))}
	if needReply {
		hdr.Flags |= VhostUserNeedReply
	}
	buf := make([]byte, 12+len(payload))
	hdr.Encode(buf[:12])
	copy(buf[12:], payload)
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("write request %d: %v", request, err)
	}
}

// sendRecv encodes a vhost-user request, writes it, and reads one reply back
// into hdrOut/bodyOut. It fails the test on I/O errors.
func sendRecv(t *testing.T, c net.Conn, request uint32, needReply bool, payload []byte) (hdrOut VhostUserMsgHeader, bodyOut []byte) {
	t.Helper()
	send(t, c, request, needReply, payload)

	rbuf := make([]byte, 4096)
	n, err := c.Read(rbuf)
	if err != nil {
		t.Fatalf("read reply for %d: %v", request, err)
	}
	if n < 12 {
		t.Fatalf("short reply %d bytes", n)
	}
	if err := hdrOut.Decode(rbuf[:12]); err != nil {
		t.Fatalf("decode reply header: %v", err)
	}
	bodyOut = rbuf[12:n]
	return
}

// TestProtocolFeatureBits: F_MQ must be bit 0, INBAND_NOTIFY bit 14,
// CONFIG bit 9, REPLY_ACK bit 3. The guest driver matches on exact numbers.
func TestProtocolFeatureBits(t *testing.T) {
	if protoFMQ != 1<<0 {
		t.Errorf("protoFMQ = %d, want 1<<0", protoFMQ)
	}
	if protoFInbandNotif != 1<<14 {
		t.Errorf("protoFInbandNotif = %d, want 1<<14", protoFInbandNotif)
	}
	if protoFConfig != 1<<9 {
		t.Errorf("protoFConfig = %d, want 1<<9", protoFConfig)
	}
	if protoFReplyAck != 1<<3 {
		t.Errorf("protoFReplyAck = %d, want 1<<3", protoFReplyAck)
	}
}

// TestGetProtocolFeatures_AdvertisesConfigForBlk: blk must offer F_CONFIG so
// the guest issues GET_CONFIG; the advertised bits must decode to the right
// numbers (#1).
func TestGetProtocolFeatures_AdvertisesConfigForBlk(t *testing.T) {
	_, _, c := startTestServer(t, 4*1024) // 4 KiB image

	hdr, body := sendRecv(t, c, VhostUserGetProtocolFeatures, true, nil)
	if hdr.Request != VhostUserGetProtocolFeatures {
		t.Fatalf("reply request = %d, want %d", hdr.Request, VhostUserGetProtocolFeatures)
	}
	if hdr.Flags&VhostUserReplyMask == 0 {
		t.Errorf("reply missing REPLY flag")
	}
	if len(body) != 8 {
		t.Fatalf("body len = %d, want 8 (u64 features)", len(body))
	}
	got := binary.LittleEndian.Uint64(body)
	// Blk must advertise REPLY_ACK (bit 3) and CONFIG (bit 9).
	if got&protoFReplyAck == 0 {
		t.Errorf("blk proto features %#x missing REPLY_ACK (bit 3)", got)
	}
	if got&protoFConfig == 0 {
		t.Errorf("blk proto features %#x missing CONFIG (bit 9)", got)
	}
	// Must NOT accidentally set unrelated bits the old values did.
	if got&(1<<4) != 0 && protoFMQ == 1<<0 {
		t.Errorf("blk proto features %#x sets bit 4 (was old wrong MQ)", got)
	}
}

// TestGetQueueBound: getQueue must return nil past maxQueues instead of
// allocating unbounded memory (#10).
func TestGetQueueBound(t *testing.T) {
	srv := &Server{queues: make([]*VirtQueue, 0, 2)}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if q := srv.getQueue(0); q == nil {
		t.Fatal("getQueue(0) = nil, want a queue")
	}
	if q := srv.getQueue(maxQueues - 1); q == nil {
		t.Fatal("getQueue(maxQueues-1) = nil, want a queue")
	}
	if q := srv.getQueue(maxQueues); q != nil {
		t.Errorf("getQueue(maxQueues) = %v, want nil (out of range)", q)
	}
	if q := srv.getQueue(1 << 20); q != nil {
		t.Errorf("getQueue(huge) = %v, want nil (would allocate unbounded)", q)
	}
}

// TestSetVringNum_RejectsInvalid: num=0 (would divide by zero), non-power-of-
// two, and oversized values must be rejected, leaving vq.Num unchanged (#2).
func TestSetVringNum_RejectsInvalid(t *testing.T) {
	srv, _, c := startTestServer(t, 4*1024)

	cases := []uint32{0, 3, 5, 6, 7, 9, 100, 32769}
	for _, num := range cases {
		payload := make([]byte, 8)
		binary.LittleEndian.PutUint32(payload[0:4], 0) // idx 0
		binary.LittleEndian.PutUint32(payload[4:8], num)
		// Negotiate REPLY_ACK first so the server can return an error ack.
		// Use NEED_REPLY so the request/reply framing keeps each message in its
		// own ReadMsgUnix on the server (avoids two client writes being coalesced
		// into one server read, which the single-msg-per-read loop would mishandle).
		negotiateReplyAck(t, c)
		hdr, body := sendRecv(t, c, VhostUserSetVringNum, true, payload)
		_ = hdr
		// With REPLY_ACK negotiated, an invalid size replies with non-zero u64.
		if len(body) >= 8 && binary.LittleEndian.Uint64(body) == 0 {
			t.Errorf("invalid num=%d accepted (ack payload said success)", num)
		}
	}
	srv.mu.Lock()
	var num uint32
	if len(srv.queues) > 0 && srv.queues[0] != nil {
		num = srv.queues[0].Num
	}
	srv.mu.Unlock()
	if num != 0 {
		t.Errorf("vq[0].Num = %d after all-invalid SET_VRING_NUM, want unchanged (0)", num)
	}
}

// TestSetVringNum_AcceptsValid: a power-of-two size is stored.
func TestSetVringNum_AcceptsValid(t *testing.T) {
	srv, _, c := startTestServer(t, 4*1024)
	negotiateReplyAck(t, c)
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint32(payload[0:4], 1) // idx 1
	binary.LittleEndian.PutUint32(payload[4:8], 64)
	// NEED_REPLY so the server acks; the ack is also the synchronization that
	// guarantees the queue has been allocated before we inspect srv.queues.
	hdr, body := sendRecv(t, c, VhostUserSetVringNum, true, payload)
	if hdr.Size != 8 || (len(body) >= 8 && binary.LittleEndian.Uint64(body) != 0) {
		t.Fatalf("valid SET_VRING_NUM not acked as success: %+v %v", hdr, body)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.queues) <= 1 || srv.queues[1] == nil {
		t.Fatal("queue 1 not allocated")
	}
	if srv.queues[1].Num != 64 {
		t.Errorf("vq[1].Num = %d, want 64", srv.queues[1].Num)
	}
}

// TestGetVringBase_ReplyLayout: reply must be 8 bytes (u32 index, u32 num),
// not the old 4-byte layout that put `last` in the index field (#3).
func TestGetVringBase_ReplyLayout(t *testing.T) {
	srv, _, c := startTestServer(t, 4*1024)
	negotiateReplyAck(t, c)
	// Set LastAvail via SET_VRING_BASE with NEED_REPLY so the request has its
	// own reply framing (the server loop consumes one message per ReadMsgUnix).
	pbase := make([]byte, 8)
	binary.LittleEndian.PutUint32(pbase[0:4], 0)
	binary.LittleEndian.PutUint32(pbase[4:8], 7)
	send(t, c, VhostUserSetVringBase, true, pbase)
	ack := make([]byte, 20)
	if _, err := c.Read(ack); err != nil {
		t.Fatalf("read SetVringBase ack: %v", err)
	}

	req := make([]byte, 4)
	binary.LittleEndian.PutUint32(req[0:4], 0) // ask for queue 0
	hdr, body := sendRecv(t, c, VhostUserGetVringBase, true, req)
	_ = hdr
	if len(body) != 8 {
		t.Fatalf("GET_VRING_BASE body len = %d, want 8 (u32 index + u32 num)", len(body))
	}
	idx := binary.LittleEndian.Uint32(body[0:4])
	num := binary.LittleEndian.Uint32(body[4:8])
	if idx != 0 {
		t.Errorf("reply index = %d, want 0 (requested queue)", idx)
	}
	if num != 7 {
		t.Errorf("reply num (last avail) = %d, want 7", num)
	}
	// After GET_VRING_BASE the processor flag must be cleared so a later
	// SET_VRING_KICK can start fresh.
	srv.mu.Lock()
	vq := srv.queues[0]
	srv.mu.Unlock()
	if vq != nil && vq.processorStarted {
		t.Errorf("processorStarted still true after GET_VRING_BASE stop")
	}
}

// negotiateReplyAck sends SET_PROTOCOL_FEATURES with REPLY_ACK and NEED_REPLY,
// then drains the ack. Using NEED_REPLY here keeps each vhost-user message in
// its own ReadMsgUnix on the server side so two rapid client writes are not
// coalesced into a single read (the server loop consumes one message per read).
func negotiateReplyAck(t *testing.T, c net.Conn) {
	t.Helper()
	pf := make([]byte, 8)
	binary.LittleEndian.PutUint64(pf, protoFReplyAck)
	send(t, c, VhostUserSetProtocolFeatures, true, pf)
	ack := make([]byte, 20)
	if _, err := c.Read(ack); err != nil {
		t.Fatalf("read SetProtocolFeatures ack: %v", err)
	}
}

// TestReplyAck_PayloadIsU64: when REPLY_ACK is negotiated and a request sets
// NEED_REPLY, the fallback reply must be a u64 payload (size=8), not a bare
// header (size=0) (#8).
func TestReplyAck_PayloadIsU64(t *testing.T) {
	_, _, c := startTestServer(t, 4*1024)
	negotiateReplyAck(t, c)

	// SET_OWNER with NEED_REPLY: no inline handler, should hit the fallback.
	hdr, body := sendRecv(t, c, VhostUserSetOwner, true, nil)
	if hdr.Flags&VhostUserReplyMask == 0 {
		t.Errorf("reply missing REPLY flag")
	}
	if hdr.Size != 8 {
		t.Errorf("SET_OWNER ack size = %d, want 8 (u64 payload)", hdr.Size)
	}
	if len(body) != 8 {
		t.Fatalf("ack body len = %d, want 8", len(body))
	}
	if v := binary.LittleEndian.Uint64(body); v != 0 {
		t.Errorf("ack payload = %d, want 0 (success)", v)
	}
}

// TestReplyAck_NotNegotiated_NoFallback: if REPLY_ACK was not negotiated, a
// NEED_REPLY request must NOT produce a fallback empty reply (the old code
// always sent one, desyncing the stream).
func TestReplyAck_NotNegotiated_NoFallback(t *testing.T) {
	_, _, c := startTestServer(t, 4*1024)
	// Deliberately do NOT negotiate REPLY_ACK. Send SET_OWNER with NEED_REPLY.
	// Per the fallback path, the server should not write a reply. We cannot
	// easily assert "no bytes" on a stream conn without risking a blocking
	// read; instead set a read deadline and assert timeout.
	c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 64)
	if _, err := c.Write(encodeMsg(VhostUserSetOwner, true, nil)); err != nil {
		t.Fatalf("write: %v", err)
	}
	n, err := c.Read(buf)
	if err == nil {
		t.Errorf("got unsolicited %d-byte reply without REPLY_ACK negotiated", n)
	}
}

// TestGetConfig_SlicesByOffsetSize: GET_CONFIG must honor the requested
// offset and size and return exactly `size` bytes, zero-filled past the
// exposed config (#9).
func TestGetConfig_SlicesByOffsetSize(t *testing.T) {
	const imgSize = 8 * 1024 // 8 KiB => 16 sectors
	_, _, c := startTestServer(t, imgSize)

	// Read capacity (first 8 bytes) at offset 0 size 8.
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint32(payload[0:4], 0) // offset
	binary.LittleEndian.PutUint32(payload[4:8], 8) // size
	hdr, body := sendRecv(t, c, VhostUserGetConfig, false, payload)
	_ = hdr
	if len(body) != 8 {
		t.Fatalf("GET_CONFIG body len = %d, want 8", len(body))
	}
	cap := binary.LittleEndian.Uint64(body)
	if cap != 16 {
		t.Errorf("capacity = %d sectors, want 16 (8KiB/512)", cap)
	}

	// Read a window that straddles the end of our config: must be zero-filled,
	// not short.
	binary.LittleEndian.PutUint32(payload[0:4], virtioBlkCfgLen-4) // offset near end
	binary.LittleEndian.PutUint32(payload[4:8], 12)                // size past end
	_, body = sendRecv(t, c, VhostUserGetConfig, false, payload)
	if len(body) != 12 {
		t.Errorf("GET_CONFIG straddle body len = %d, want 12", len(body))
	}
}

// TestSetVringCall_ReplacesFd: a second SET_VRING_CALL must swap the
// server-side CallFd to the newly-passed fd and close the previous one (#4).
// File descriptors passed via SCM_RIGHTS are duplicated by the kernel, so the
// numeric fd the server receives differs from the one the test sent; we
// therefore assert that a valid fd is installed and that a second call changes
// it (proving replacement rather than ignoring the second pass).
func TestSetVringCall_ReplacesFd(t *testing.T) {
	srv, _, c := startTestServer(t, 4*1024)
	negotiateReplyAck(t, c)
	fd1, _ := openPipe()
	fd2, _ := openPipe()
	t.Cleanup(func() {
		closeFd(fd1)
		closeFd(fd2)
	})

	sendCall := func(idx uint32, fd int) {
		payload := make([]byte, 8)
		binary.LittleEndian.PutUint64(payload, uint64(idx))
		writeMsgWithFDs(t, c, VhostUserSetVringCall, true, payload, fd)
		// Drain the REPLY_ACK so this message is framed on its own server read.
		ack := make([]byte, 20)
		if _, err := c.Read(ack); err != nil {
			t.Fatalf("read SET_VRING_CALL ack: %v", err)
		}
	}
	sendCall(0, fd1)
	srv.mu.Lock()
	vq0 := srv.queues[0]
	got1 := noFd
	if vq0 != nil {
		got1 = vq0.CallFd
	}
	srv.mu.Unlock()
	if got1 < 0 {
		t.Fatalf("after first SET_VRING_CALL, CallFd = %d, want a valid fd", got1)
	}

	sendCall(0, fd2)
	srv.mu.Lock()
	got2 := noFd
	if vq0 != nil {
		got2 = vq0.CallFd
	}
	srv.mu.Unlock()
	if got2 < 0 {
		t.Errorf("after second SET_VRING_CALL, CallFd = %d, want a valid fd", got2)
	}
	// The second pass must have replaced the first fd with a different one;
	// otherwise the server would be ignoring repeated SET_VRING_CALL.
	if got2 == got1 {
		t.Errorf("second SET_VRING_CALL did not replace CallFd (still %d)", got2)
	}
	// Clean up the fds now held by the server so they are not left open after
	// the queue is dropped.
	if got2 >= 0 {
		closeFd(got2)
	}
}

// ---- helpers ----

func encodeMsg(request uint32, needReply bool, payload []byte) []byte {
	hdr := VhostUserMsgHeader{Request: request, Size: uint32(len(payload))}
	if needReply {
		hdr.Flags |= VhostUserNeedReply
	}
	buf := make([]byte, 12+len(payload))
	hdr.Encode(buf[:12])
	copy(buf[12:], payload)
	return buf
}

func writeMsgWithFDs(t *testing.T, c net.Conn, request uint32, needReply bool, payload []byte, fds ...int) {
	t.Helper()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		t.Fatalf("conn is not *net.UnixConn: %T", c)
	}
	buf := encodeMsg(request, needReply, payload)
	oob := syscall.UnixRights(fds...)
	if _, _, err := uc.WriteMsgUnix(buf, oob, nil); err != nil {
		t.Fatalf("WriteMsgUnix: %v", err)
	}
}

func openPipe() (int, int) {
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		return -1, -1
	}
	return p[0], p[1]
}

func closeFd(fd int) {
	if fd >= 0 {
		syscall.Close(fd)
	}
}
