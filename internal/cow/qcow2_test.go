package cow

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
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

// TestCreateOverlay_DefaultGeometry: the default overlay must be 4 KiB
// clusters with metadata preallocated — 4 KiB matches the ext4 block / guest
// page size so aligned writes cost exactly one data cluster (no 60 KiB
// read-modify-write tail), and preallocated L2 tables remove the first-write
// metadata allocation storms.
func TestCreateOverlay_DefaultGeometry(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	// Sparse 64 MiB base.
	bf, err := os.OpenFile(base, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("create base: %v", err)
	}
	if err := bf.Truncate(64 << 20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	bf.Close()

	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create overlay: %v", err)
	}
	f, err := os.Open(overlay)
	if err != nil {
		t.Fatalf("open overlay: %v", err)
	}
	defer f.Close()
	var hdr [qcow2HeaderLen]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if cb := binary.BigEndian.Uint32(hdr[0x14:]); cb != 12 {
		t.Errorf("default cluster_bits = %d, want 12 (4 KiB)", cb)
	}
	l1Size := binary.BigEndian.Uint32(hdr[0x24:])
	l1Off := binary.BigEndian.Uint64(hdr[0x28:])

	// Metadata preallocation: every L1 entry must point at a linked L2 table.
	// 64 MiB / (512 entries * 4 KiB) = 32 L2 tables.
	if l1Size != 32 {
		t.Errorf("l1_size = %d, want 32 (64 MiB at 4 KiB clusters)", l1Size)
	}
	buf := make([]byte, l1Size*8)
	if _, err := f.ReadAt(buf, int64(l1Off)); err != nil {
		t.Fatalf("read L1: %v", err)
	}
	for i := uint32(0); i < l1Size; i++ {
		e := binary.BigEndian.Uint64(buf[i*8:])
		if e&l1eOffsetMask == 0 {
			t.Fatalf("L1[%d] not preallocated (entry %#x)", i, e)
		}
		if e&oflagCopied == 0 {
			t.Errorf("L1[%d] missing COPIED flag (qemu-img check would fail)", i)
		}
	}
	// 32 L2 tables at 4 KiB = 128 KiB of preallocated metadata beyond the
	// fixed header/reftable/refblock/L1 clusters.
	st, _ := f.Stat()
	wantMin := int64(l1Off) + int64(l1Size*8) + int64(l1Size)*4096
	if st.Size() < wantMin {
		t.Errorf("overlay size %d < preallocated size %d (L2 tables missing?)", st.Size(), wantMin)
	}
}

// TestQcow2Write_AlignedWriteAmplification: a guest-4K-aligned 4K write on a
// default (4 KiB cluster) overlay must grow the host file by exactly one
// cluster — pure data append, no CoW read, no L2/refcount-block allocation
// (those are preallocated). This is the regression test for the 64 KiB
// cluster write amplification (4K write => 60K backing read + 64K alloc).
func TestQcow2Write_AlignedWriteAmplification(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	bf, err := os.OpenFile(base, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("create base: %v", err)
	}
	if err := bf.Truncate(16 << 20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	bf.Close()

	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create overlay: %v", err)
	}
	be := openWritable(t, overlay)

	// 4 KiB write at a 4 KiB-aligned guest offset.
	data := patterned(0xAB, 4096)
	if _, err := be.WriteAt(data, 8192); err != nil {
		t.Fatalf("aligned write: %v", err)
	}
	if err := be.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	st, err := os.Stat(overlay)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// virtual size is untouched; HOST file must grow by exactly one cluster.
	grew := st.Size() - preallocSize(t, overlay)
	if grew != 4096 {
		t.Errorf("host file grew by %d bytes for one 4 KiB aligned write, want 4096 (pure data append)", grew)
	}

	// Read back through the chain: the written data plus untouched base.
	got := make([]byte, 4096)
	if _, err := be.ReadAt(got, 8192); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("aligned write readback mismatch")
	}
	be.Close()
}

// preallocSize reads the overlay header and returns the byte offset just past
// the preallocated L2 tables (= the file size right after create).
func preallocSize(t *testing.T, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var hdr [qcow2HeaderLen]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		t.Fatalf("read header: %v", err)
	}
	l1Size := binary.BigEndian.Uint32(hdr[0x24:])
	l1Off := binary.BigEndian.Uint64(hdr[0x28:])
	cb := binary.BigEndian.Uint32(hdr[0x14:])
	cs := int64(1) << cb
	l1Clusters := (int64(l1Size)*8 + cs - 1) / cs
	return int64(l1Off) + l1Clusters*cs + int64(l1Size)*cs
}

// TestQcow2_ForeignClusterGeometry: images created with non-default cluster
// sizes (e.g. by qemu-img or older PVM versions) must still read and write
// correctly — geometry comes from the header, not the package constant.
func TestQcow2_ForeignClusterGeometry(t *testing.T) {
	for _, bits := range []uint32{9, 13, 16, 20} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "base.img")
			bf, err := os.OpenFile(base, os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				t.Fatalf("create base: %v", err)
			}
			if err := bf.Truncate(8 << 20); err != nil {
				t.Fatalf("truncate: %v", err)
			}
			bf.Close()

			overlay := filepath.Join(dir, "ov.qcow2")
			opt := OverlayOpt{ClusterBits: bits, PreallocMetadata: bits > 9}
			if err := CreateOverlayWithOptions(context.Background(), base, overlay, opt); err != nil {
				t.Fatalf("create overlay (bits=%d): %v", bits, err)
			}

			be := openWritable(t, overlay)
			cs := int64(1) << bits
			// Partial write (forces CoW of the backing view), full write,
			// and an unaligned span crossing a cluster boundary.
			if _, err := be.WriteAt(patterned(0x31, 100), cs+7); err != nil {
				t.Fatalf("partial write: %v", err)
			}
			if _, err := be.WriteAt(patterned(0x32, int(cs)), 3*cs); err != nil {
				t.Fatalf("full write: %v", err)
			}
			if _, err := be.WriteAt(patterned(0x33, int(cs)+50), 5*cs-25); err != nil {
				t.Fatalf("crossing write: %v", err)
			}
			// Commit and verify via the chain reader.
			if err := be.Sync(); err != nil {
				t.Fatalf("sync: %v", err)
			}
			be.Close()

			img, err := openGuestImage(overlay)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer img.Close()
			got := make([]byte, int(cs)+50)
			if _, err := img.ReadAt(got, 5*cs-25); err != nil {
				t.Fatalf("read crossing region: %v", err)
			}
			if !bytes.Equal(got, patterned(0x33, int(cs)+50)) {
				t.Error("crossing write readback mismatch")
			}
		})
	}
}

// TestQcow2_ClusterBitsRange: cluster_bits outside the qcow2 spec range
// (9..21) must be rejected at create time, not produce a corrupt image.
func TestQcow2_ClusterBitsRange(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x01, 8192))
	for _, bits := range []uint32{8, 22, 32} {
		err := CreateOverlayWithOptions(context.Background(), base, filepath.Join(dir, "ov.qcow2"),
			OverlayOpt{ClusterBits: bits})
		if err == nil {
			t.Errorf("cluster_bits %d accepted, want rejection", bits)
		}
	}
}
