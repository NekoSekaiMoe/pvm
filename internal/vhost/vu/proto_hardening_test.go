package vu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestBufPoolBuckets pins the size bucketing used by the bounce-buffer pool.
func TestBufPoolBuckets(t *testing.T) {
	cases := []struct {
		size int
		want int // expected bucket capacity
	}{
		{1, 512},
		{512, 512},
		{513, 1024},
		{4096, 4096},
		{65536, 65536},
	}
	for _, c := range cases {
		if got := bufPoolMinSize << bufBucket(c.size); got != c.want {
			t.Errorf("bucket(%d) = %d, want %d", c.size, got, c.want)
		}
	}
}

// TestGetPutBufRoundTrip verifies pooled buffers keep their capacity across
// get/put cycles (so reuse actually happens) and honor the requested length.
func TestGetPutBufRoundTrip(t *testing.T) {
	buf := getBuf(1000)
	if cap(buf) != 1024 || len(buf) != 1000 {
		t.Fatalf("getBuf(1000): len=%d cap=%d, want len=1000 cap=1024", len(buf), cap(buf))
	}
	putBuf(buf)
	buf2 := getBuf(900)
	// sync.Pool does NOT guarantee object identity after Put/Get (the GC may
	// drop pooled objects between the two calls), so assert the stable
	// contract instead: same bucket capacity, correct length.
	if cap(buf2) != 1024 || len(buf2) != 900 {
		t.Fatalf("getBuf(900): len=%d cap=%d, want len=900 cap=1024", len(buf2), cap(buf2))
	}
	putBuf(buf2)

	// Non-bucket capacities must not be pooled.
	putBuf(make([]byte, 100)) // cap 100: ignored
}

// toConnPair builds two conns over a unix socketpair (same pattern as
// vu_test.go's TestReplyClearsNeedReply).
func toConnPair(t *testing.T) (*conn, *conn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	toConn := func(fd int) *conn {
		f := os.NewFile(uintptr(fd), "sock")
		defer f.Close()
		uc, err := net.FileConn(f)
		if err != nil {
			t.Fatalf("FileConn: %v", err)
		}
		c := newConn(uc.(*net.UnixConn))
		t.Cleanup(func() { c.c.Close() })
		return c
	}
	return toConn(fds[0]), toConn(fds[1])
}

// TestRecvRejectsWrongProtocolVersion pins the vhost-user version check:
// headers whose version bits are not 1 must fail the recv, not be silently
// dispatched to handlers.
func TestRecvRejectsWrongProtocolVersion(t *testing.T) {
	server, client := toConnPair(t)

	var raw [12 + 8]byte
	binary.LittleEndian.PutUint32(raw[0:], reqSetVringEnable)
	binary.LittleEndian.PutUint32(raw[4:], 1|flagNeedReply|0x2) // version bits = 3
	binary.LittleEndian.PutUint32(raw[8:], 8)
	if _, err := client.c.Write(raw[:]); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := server.recv(); err == nil {
		t.Fatal("recv accepted a message with invalid protocol version")
	}
}

// TestSendRecvBufferReuse sends several messages through one conn and checks
// each payload decodes correctly — guards against the reusable receive/send
// buffers aliasing or corrupting consecutive messages.
func TestSendRecvBufferReuse(t *testing.T) {
	server, client := toConnPair(t)

	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 8),
		bytes.Repeat([]byte{0xBB}, 264), // mem-table sized
		bytes.Repeat([]byte{0xCC}, 64),
	}
	go func() {
		for i, p := range payloads {
			if err := client.send(uint32(i+1), 1, p); err != nil { //nolint:gosec // fixed values
				t.Errorf("send %d: %v", i, err)
				return
			}
		}
	}()
	for i, want := range payloads {
		m, err := server.recv()
		if err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		if !bytes.Equal(m.payload, want) {
			t.Fatalf("payload %d corrupted: got %x… want %x…", i, m.payload[:4], want[:4])
		}
		if err := server.reply(m, []byte("replied!")); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}
}

// TestReplyPayloadIndependentOfReceiveBuffer ensures reply() uses an
// independent send buffer: a reply payload slice that aliases the
// reusable receive buffer must not self-overwrite while the reply is in
// flight.
func TestReplyPayloadIndependentOfReceiveBuffer(t *testing.T) {
	server, client := toConnPair(t)

	done := make(chan error, 1)
	go func() {
		p := bytes.Repeat([]byte{0x42}, 16)
		if err := client.send(reqGetFeatures, 1|flagNeedReply, p); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 12+8)
		if _, err := io.ReadFull(client.c, buf); err != nil {
			done <- err
			return
		}
		size := binary.LittleEndian.Uint32(buf[8:])
		if int(size) != 8 {
			done <- errReplySize
			return
		}
		if !bytes.Equal(buf[12:], bytes.Repeat([]byte{0x42}, 8)) {
			done <- errReplyMismatch
			return
		}
		done <- nil
	}()

	m, err := server.recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	// Reply with a slice OF the receive buffer: the reply must go out from
	// an independent send buffer, so the bytes on the wire match the payload
	// as of reply() even though the receive buffer is mutated afterwards.
	if err := server.reply(m, m.payload[:8]); err != nil {
		t.Fatalf("reply: %v", err)
	}
	for i := range m.payload {
		m.payload[i] = 0x77 // mutate after reply: client must still see 0x42s
	}
	if err := <-done; err != nil {
		t.Fatalf("client roundtrip: %v", err)
	}
}

var (
	errReplyMismatch = errors.New("reply payload mismatch")
	errReplySize     = errors.New("reply payload size mismatch")
)
