package cow

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// writeGuestCluster simulates a guest write into a qcow2 image: it appends a
// data cluster at EOF and points the L1/L2 tables at it. Refcounts are NOT
// updated — the pure-Go reader (and qemu-img convert) don't consult them for
// reading. This is test-only plumbing standing in for qemu-storage-daemon.
func writeGuestCluster(t *testing.T, imagePath string, guestCluster uint64, data []byte) {
	t.Helper()
	if len(data) > clusterSize {
		t.Fatalf("data larger than one cluster")
	}
	f, err := os.OpenFile(imagePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", imagePath, err)
	}
	defer f.Close()

	var hdrBuf [qcow2HeaderLen]byte
	if _, err := f.ReadAt(hdrBuf[:], 0); err != nil {
		t.Fatalf("read header: %v", err)
	}
	l1Off := binary.BigEndian.Uint64(hdrBuf[0x28:])

	l1Idx := guestCluster / (clusterSize / 8)
	l2Idx := guestCluster % (clusterSize / 8)

	// Align EOF to cluster boundary for a fresh allocation.
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	eof := uint64(st.Size())
	if eof%clusterSize != 0 {
		t.Fatalf("qcow2 file size %#x not cluster-aligned", eof)
	}
	alloc := func() uint64 {
		st, _ := f.Stat()
		off := uint64(st.Size())
		if _, err := f.WriteAt(make([]byte, clusterSize), int64(off)); err != nil {
			t.Fatalf("extend file: %v", err)
		}
		return off
	}

	// Fetch or allocate the L2 table.
	var l1eBuf [8]byte
	if _, err := f.ReadAt(l1eBuf[:], int64(l1Off+l1Idx*8)); err != nil {
		t.Fatalf("read L1 entry: %v", err)
	}
	l2Off := binary.BigEndian.Uint64(l1eBuf[:]) & l1eOffsetMask
	if l2Off == 0 {
		l2Off = alloc()
		binary.BigEndian.PutUint64(l1eBuf[:], l2Off|oflagCopied)
		if _, err := f.WriteAt(l1eBuf[:], int64(l1Off+l1Idx*8)); err != nil {
			t.Fatalf("write L1 entry: %v", err)
		}
	}

	// Write the data cluster and point the L2 entry at it.
	hostOff := alloc()
	padded := make([]byte, clusterSize)
	copy(padded, data)
	if _, err := f.WriteAt(padded, int64(hostOff)); err != nil {
		t.Fatalf("write data cluster: %v", err)
	}
	var l2eBuf [8]byte
	binary.BigEndian.PutUint64(l2eBuf[:], hostOff|oflagCopied)
	if _, err := f.WriteAt(l2eBuf[:], int64(l2Off+l2Idx*8)); err != nil {
		t.Fatalf("write L2 entry: %v", err)
	}
}

// patterned returns a deterministic non-zero content block.
func patterned(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i%251)
	}
	return b
}

func mustWriteRaw(t *testing.T, path string, off int64, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("create raw %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteAt(data, off); err != nil {
		t.Fatalf("write raw: %v", err)
	}
}

// TestConvertToRaw_RawBacking: overlay data must shadow the raw base, base
// data must show through where the overlay is unallocated.
func TestConvertToRaw_RawBacking(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	baseContent := patterned(0x10, 3*clusterSize)
	mustWriteRaw(t, base, 0, baseContent)
	// a marker in a cluster the guest never touches (12, beyond the guest
	// patch at cluster 10) — qcow2 CoW is cluster-granular, so once the guest
	// allocates a cluster the WHOLE cluster comes from the overlay.
	marker := patterned(0x77, 4096)
	mustWriteRaw(t, base, 12*clusterSize+123, marker)

	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create overlay: %v", err)
	}
	// guest writes: shadow cluster 1 entirely, part of the marker region
	shadow := patterned(0xA0, clusterSize)
	writeGuestCluster(t, overlay, 1, shadow)
	patch := []byte("guest-was-here")
	writeGuestCluster(t, overlay, 10, append(patch, make([]byte, 100)...))

	dest := filepath.Join(dir, "out.raw")
	if err := CommitOverlay(context.Background(), overlay, dest); err != nil {
		t.Fatalf("commit: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	// base file size determines the virtual size: 10*cluster+123+4096
	baseSt, _ := os.Stat(base)
	wantSize := uint64(baseSt.Size())
	if uint64(len(got)) != wantSize {
		t.Fatalf("dest size = %d, want %d", len(got), wantSize)
	}
	// cluster 0: from base
	if !bytes.Equal(got[:clusterSize], baseContent[:clusterSize]) {
		t.Error("cluster 0 should come from base")
	}
	// cluster 1: shadowed by overlay
	if !bytes.Equal(got[clusterSize:2*clusterSize], shadow) {
		t.Error("cluster 1 should come from overlay")
	}
	// cluster 2: from base
	if !bytes.Equal(got[2*clusterSize:3*clusterSize], baseContent[2*clusterSize:]) {
		t.Error("cluster 2 should come from base")
	}
	// cluster 10: guest patch + zeros (whole cluster shadowed by overlay)
	wantCluster10 := append(append([]byte("guest-was-here"), make([]byte, 100)...), make([]byte, clusterSize-114)...)
	if !bytes.Equal(got[10*clusterSize:11*clusterSize], wantCluster10) {
		t.Error("cluster 10 should be the guest cluster (patch + zeros)")
	}
	// cluster 12: untouched, base marker shows through
	if !bytes.Equal(got[12*clusterSize+123:12*clusterSize+123+uint64(len(marker))], marker) {
		t.Error("base marker should show through in untouched cluster 12")
	}
}

// TestConvertToRaw_Qcow2Chain: two levels of qcow2 overlay over a raw base.
func TestConvertToRaw_Qcow2Chain(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x01, 2*clusterSize))

	mid := filepath.Join(dir, "mid.qcow2")
	if err := CreateOverlay(context.Background(), base, mid); err != nil {
		t.Fatalf("create mid: %v", err)
	}
	midData := patterned(0x22, clusterSize)
	writeGuestCluster(t, mid, 0, midData)

	top := filepath.Join(dir, "top.qcow2")
	if err := CreateOverlay(context.Background(), mid, top); err != nil {
		t.Fatalf("create top: %v", err)
	}
	topData := patterned(0x33, 512)
	writeGuestCluster(t, top, 0, topData)

	dest := filepath.Join(dir, "out.raw")
	if err := CommitOverlay(context.Background(), top, dest); err != nil {
		t.Fatalf("commit: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	// Cluster granularity CoW: top allocated cluster 0, so the WHOLE cluster
	// reads from top (512 bytes of data + zeros); mid's cluster-0 data and the
	// base are fully shadowed. Cluster 1 is untouched by mid and top, so the
	// base shows through there.
	wantCluster0 := append(patterned(0x33, 512), make([]byte, clusterSize-512)...)
	if !bytes.Equal(got[:clusterSize], wantCluster0) {
		t.Error("cluster 0 should be top's cluster (data + zeros)")
	}
	if !bytes.Equal(got[clusterSize:2*clusterSize], patterned(0x01, 2*clusterSize)[clusterSize:]) {
		t.Error("base should show through in cluster 1")
	}
}

// TestConvertToRaw_CompressedClusterRejected: compressed clusters are out of
// scope (we never create them); the reader must fail loudly, not silently
// return garbage.
func TestConvertToRaw_CompressedClusterRejected(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x01, clusterSize))
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create overlay: %v", err)
	}

	// Forge an L2 entry with the COMPRESSED bit set.
	writeGuestCluster(t, overlay, 0, patterned(0x99, 64)) // allocates L2 table
	f, err := os.OpenFile(overlay, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var hdrBuf [qcow2HeaderLen]byte
	f.ReadAt(hdrBuf[:], 0)
	l1Off := binary.BigEndian.Uint64(hdrBuf[0x28:])
	var l1eBuf [8]byte
	f.ReadAt(l1eBuf[:], int64(l1Off))
	l2Off := binary.BigEndian.Uint64(l1eBuf[:]) & l1eOffsetMask
	binary.BigEndian.PutUint64(l1eBuf[:], 0x123456|oflagCompressed)
	if _, err := f.WriteAt(l1eBuf[:], int64(l2Off)); err != nil { // L2[0]
		t.Fatalf("forge L2 entry: %v", err)
	}
	f.Close()

	err = CommitOverlay(context.Background(), overlay, filepath.Join(dir, "out.raw"))
	if err == nil {
		t.Fatal("expected error for compressed cluster")
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("compressed")) {
		t.Errorf("error should mention compressed clusters, got: %v", err)
	}
}

// TestConvertToRaw_ContextCanceled: a canceled context aborts the flatten.
func TestConvertToRaw_ContextCanceled(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x01, clusterSize))
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create overlay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CommitOverlay(ctx, overlay, filepath.Join(dir, "out.raw")); err == nil {
		t.Fatal("expected context.Canceled")
	}
}

// TestQcow2_DifferentialQemuImg cross-validates the pure-Go writer and reader
// against the real qemu-img when one is available (PATH or the vendored
// build under /tmp). Skipped otherwise.
func TestQcow2_DifferentialQemuImg(t *testing.T) {
	qemuImg, err := exec.LookPath("qemu-img")
	if err != nil {
		for _, cand := range []string{"/tmp/qemu-img-oneshot", "/tmp/qemu-img-slim/qemu-img"} {
			if _, err := os.Stat(cand); err == nil {
				qemuImg = cand
				break
			}
		}
	}
	if qemuImg == "" {
		t.Skip("no qemu-img binary available for differential test")
	}

	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x5A, 2*clusterSize))

	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create overlay: %v", err)
	}

	// 1. qemu-img must accept our metadata layout: info parses, check passes.
	if out, err := exec.Command(qemuImg, "info", "--backing-chain", overlay).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img info rejected Go-created overlay: %v: %s", err, out)
	}
	if out, err := exec.Command(qemuImg, "check", overlay).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img check failed on Go-created overlay: %v: %s", err, out)
	}

	// 2. Write through qemu-img's own qcow2 driver is covered by qemu-io;
	//    here we at least cross-check convert on a populated overlay.
	writeGuestCluster(t, overlay, 1, patterned(0xC3, clusterSize))
	goOut := filepath.Join(dir, "go.raw")
	if err := CommitOverlay(context.Background(), overlay, goOut); err != nil {
		t.Fatalf("go convert: %v", err)
	}
	qemuOut := filepath.Join(dir, "qemu.raw")
	if out, err := exec.Command(qemuImg, "convert", "-O", "raw", overlay, qemuOut).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img convert: %v: %s", err, out)
	}
	goBytes, _ := os.ReadFile(goOut)
	qemuBytes, _ := os.ReadFile(qemuOut)
	if !bytes.Equal(goBytes, qemuBytes) {
		t.Errorf("convert mismatch: go=%d bytes qemu=%d bytes", len(goBytes), len(qemuBytes))
	}
}
