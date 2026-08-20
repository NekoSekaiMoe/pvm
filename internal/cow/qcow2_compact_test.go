package cow

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Compact's contract is one-way semantics-preserving: for every guest offset,
// reading the overlay after Compact MUST return the same bytes as before.
// The tricky cases are the ones where a naive "drop zero clusters" rebuild
// would change behavior:
//
//   - a cluster explicitly written as zeros over NONZERO backing must STILL
//     read as zero (not fall through to the backing);
//   - clusters reading through to the backing must keep reading the backing;
//   - a trailing partial cluster at the end of the virtual size must survive.
//
// These tests build a source overlay, snapshot its full guest view, compact,
// and assert byte-for-byte equality plus a few invariants on sizes/stats.

const compactVirtual = 16 * 1024 * 1024 // 16 MiB: spans multiple L2 tables (4KiB clusters => 2MiB/L2 => 8 L2 tables)

// compactFixture builds a base + overlay with a pattern of writes described by
// the caller, and returns the overlay path plus the expected full guest view.
type writeOp struct {
	cluster uint64 // guest cluster index
	data    []byte // len <= clusterSize; trailing bytes left as-is from backing/zero
}

// buildOverlayWithWrites creates a base filled with a nonzero pattern (so any
// dropped-to-unallocated cluster would visibly resurrect the wrong bytes),
// creates an overlay, applies the writes, and returns the overlay path and
// the full expected guest view.
func buildOverlayWithWrites(t *testing.T, dir string, ops []writeOp) (overlay string, view []byte) {
	t.Helper()
	base := filepath.Join(dir, "base.img")
	// Nonzero backing: every byte = pattern, so a dropped cluster
	// (reads-through-to-backing) is distinguishable from a zero cluster.
	view = make([]byte, compactVirtual)
	for i := range view {
		view[i] = byte(0x10 + i%251)
	}
	mustWriteRaw(t, base, 0, view)

	overlay = filepath.Join(dir, "overlay.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	w := openWritable(t, overlay)
	for _, op := range ops {
		off := int64(op.cluster) * int64(clusterSize)
		if _, err := w.WriteAt(op.data, off); err != nil {
			t.Fatalf("WriteAt cluster %d: %v", op.cluster, err)
		}
		// reflect into the expected view (partial writes leave the rest of the
		// cluster as backing content, matching what the overlay reads).
		copy(view[off:], op.data)
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	w.Close()
	return overlay, view
}

// assertView reads the full guest view of path and asserts it equals want.
func assertView(t *testing.T, path string, want []byte) {
	t.Helper()
	img := openGuestImageFile(t, path)
	defer img.Close()
	got := make([]byte, len(want))
	n, err := img.ReadAt(got, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != len(want) {
		t.Fatalf("read length: got %d want %d", n, len(want))
	}
	if !bytes.Equal(got, want) {
		// locate first differing byte for a useful failure message
		for i := 0; i < len(want); i++ {
			if got[i] != want[i] {
				t.Fatalf("view differs at byte %d (cluster %d): got %#x want %#x",
					i, i/clusterSize, got[i], want[i])
			}
		}
		// Unreachable when bytes.Equal genuinely disagrees (the loop above
		// must find the differing byte), but guard against a silent pass.
		t.Fatalf("%s view differs from expected but no differing byte was localized", path)
	}
}

// TestCompact_PreservesContent covers the core semantics across the write
// patterns that matter: data writes, explicit zeros over nonzero backing,
// untouched (backing-read-through) clusters, and a far cluster forcing a
// second L2 table. Each scenario is a t.Run row over a write-ops table.
func TestCompact_PreservesContent(t *testing.T) {
	zeroCluster := make([]byte, clusterSize) // explicit zeros
	totalClusters := compactVirtual / clusterSize
	for _, tc := range []struct {
		name         string
		ops          []writeOp
		wantCopied   int64
		wantZeroed   int64
		wantDropped  int64 // totalClusters - clusters touched by ops
	}{
		{
			"mixed_first_and_second_l2",
			[]writeOp{
				{0, patterned(0x77, clusterSize)},   // data cluster, first L2 table
				{5, zeroCluster},                    // ZERO cluster shadowing nonzero backing
				{513, patterned(0x33, clusterSize)}, // data cluster, second L2 table
				{514, zeroCluster},                  // ZERO cluster in the second L2 table
			},
			2, 2, int64(totalClusters) - 4,
		},
		{
			"single_data_cluster",
			[]writeOp{
				{2, patterned(0x55, clusterSize)},
			},
			1, 0, int64(totalClusters) - 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			overlay, want := buildOverlayWithWrites(t, dir, tc.ops)

			st0, _ := os.Stat(overlay)
			stats, err := Compact(context.Background(), overlay)
			if err != nil {
				t.Fatalf("Compact: %v", err)
			}
			st1, _ := os.Stat(overlay)
			t.Logf("before=%d after=%d stats=%+v", st0.Size(), st1.Size(), stats)

			assertView(t, overlay, want)

			if stats.ClustersCopied != tc.wantCopied {
				t.Errorf("ClustersCopied = %d, want %d", stats.ClustersCopied, tc.wantCopied)
			}
			if stats.ClustersZeroed != tc.wantZeroed {
				t.Errorf("ClustersZeroed = %d, want %d", stats.ClustersZeroed, tc.wantZeroed)
			}
			// Every cluster NOT written by the ops is unallocated and reads
			// through to the backing, so it must be counted as dropped.
			if stats.ClustersDropped != tc.wantDropped {
				t.Errorf("ClustersDropped = %d, want %d", stats.ClustersDropped, tc.wantDropped)
			}
			if st1.Size() >= st0.Size() {
				t.Errorf("size did not shrink: before=%d after=%d", st0.Size(), st1.Size())
			}
		})
	}
}

// TestCompact_ZeroClusterShadowsBacking isolates the highest-risk invariant:
// after compaction, a guest-zeroed cluster over a nonzero backing MUST read as
// zero (not resurrect the backing bytes). This is exactly the bug a naive
// "drop the cluster to unallocated" compaction would introduce.
func TestCompact_ZeroClusterShadowsBacking(t *testing.T) {
	dir := t.TempDir()
	overlay, want := buildOverlayWithWrites(t, dir, []writeOp{
		{10, make([]byte, clusterSize)}, // zero over nonzero backing
	})
	if _, err := Compact(context.Background(), overlay); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	// want[10*cs : 11*cs] is all zero by construction; assertView checks it.
	assertView(t, overlay, want)

	// And directly: the backing at cluster 10 is nonzero, but the overlay
	// must report zero there post-compact.
	img := openGuestImageFile(t, overlay)
	got := make([]byte, clusterSize)
	if _, err := img.ReadAt(got, int64(10)*int64(clusterSize)); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt: %v", err)
	}
	img.Close()
	for i, b := range got {
		if b != 0 {
			t.Fatalf("cluster 10 byte %d = %#x, want 0 (ZERO-flag must shadow nonzero backing)", i, b)
		}
	}
}

// TestCompact_PartialTrailingCluster: a write into the very last cluster of
// the virtual size that doesn't fill the whole cluster (n < cs at EOF).
func TestCompact_PartialTrailingCluster(t *testing.T) {
	dir := t.TempDir()
	// custom virtual size that is NOT a multiple of clusterSize, so the last
	// cluster is partial.
	virtual := uint64(10*clusterSize + 1234)
	base := filepath.Join(dir, "base.img")
	view := make([]byte, virtual)
	for i := range view {
		view[i] = byte(0x20 + i%251)
	}
	mustWriteRaw(t, base, 0, view)
	overlay := filepath.Join(dir, "overlay.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	// partial write into the last cluster (1234-byte tail).
	tail := patterned(0xAB, 1234)
	w := openWritable(t, overlay)
	if _, err := w.WriteAt(tail, int64(10*clusterSize)); err != nil {
		t.Fatalf("WriteAt tail: %v", err)
	}
	copy(view[10*clusterSize:], tail)
	if err := w.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	w.Close()

	if _, err := Compact(context.Background(), overlay); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	assertView(t, overlay, view)
}

// TestCompact_StandaloneImage (no backing): every unallocated cluster reads as
// zero, so the only thing to preserve is the written data.
func TestCompact_StandaloneImage(t *testing.T) {
	dir := t.TempDir()
	// Build a standalone qcow2 (no backing) by passing an empty backing
	// path to createQcow2, then writing some clusters. An empty backingPath
	// produces a standalone image.
	img := filepath.Join(dir, "standalone.qcow2")
	if err := createQcow2(img, compactVirtual, "", "", defaultOverlayOpt); err != nil {
		t.Fatalf("createQcow2: %v", err)
	}
	w := openWritable(t, img)
	want := make([]byte, compactVirtual) // unallocated reads as zero
	c2 := patterned(0x55, clusterSize)
	if _, err := w.WriteAt(c2, int64(2)*int64(clusterSize)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	copy(want[2*clusterSize:], c2)
	if err := w.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	w.Close()

	if _, err := Compact(context.Background(), img); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	assertView(t, img, want)
}

// TestCompact_Idempotent: compacting an already-compacted overlay is a no-op
// (same reads, no error).
func TestCompact_Idempotent(t *testing.T) {
	dir := t.TempDir()
	overlay, want := buildOverlayWithWrites(t, dir, []writeOp{
		{1, patterned(0x44, clusterSize)},
		{2, make([]byte, clusterSize)},
	})
	if _, err := Compact(context.Background(), overlay); err != nil {
		t.Fatalf("Compact 1: %v", err)
	}
	st1, _ := os.Stat(overlay)
	if _, err := Compact(context.Background(), overlay); err != nil {
		t.Fatalf("Compact 2: %v", err)
	}
	st2, _ := os.Stat(overlay)
	assertView(t, overlay, want)
	// A second compact should not grow the file.
	if st2.Size() > st1.Size() {
		t.Errorf("second compact grew file: %d -> %d", st1.Size(), st2.Size())
	}
}

// TestCompact_RejectsNonQcow2: a raw image is not compactable.
func TestCompact_RejectsNonQcow2(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.img")
	mustWriteRaw(t, raw, 0, patterned(0x01, 4*clusterSize))
	if _, err := Compact(context.Background(), raw); err == nil {
		t.Fatalf("Compact on raw image: expected error, got nil")
	}
}

// TestCompact_RejectsCompressed: a hand-crafted L2 entry with the compressed
// flag must be rejected, not silently dropped.
func TestCompact_RejectsCompressed(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x10, 2*clusterSize))
	overlay := filepath.Join(dir, "overlay.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	// Open writable, then poke a compressed-flag L2 entry directly via the
	// internal writer to simulate a foreign image our writer would never
	// produce but our reader rejects.
	w := openWritable(t, overlay)
	qw := w.(*qcow2Writable)
	// cluster 3, L2 entry = oflagCompressed only (no real host data).
	if err := qw.setL2Entry(3, oflagCompressed); err != nil {
		t.Fatalf("setL2Entry: %v", err)
	}
	if err := qw.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	w.Close()

	if _, err := Compact(context.Background(), overlay); err == nil {
		t.Fatalf("Compact on compressed-cluster image: expected error, got nil")
	}
}

// TestCompact_RejectsInternalSnapshots: an image whose header declares
// internal snapshots (nb_snapshots > 0) must be rejected, because the L1
// active-table walk would skip snapshot-only clusters and silently drop them.
// We simulate a foreign image by poking the header's snapshots/
// snapshots_offset fields directly (our own create path never writes them).
func TestCompact_RejectsInternalSnapshots(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x10, 2*clusterSize))
	overlay := filepath.Join(dir, "overlay.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	w := openWritable(t, overlay)
	qw := w.(*qcow2Writable)
	// nb_snapshots at 0x3C (u32), snapshots_offset at 0x40 (u64). Set both to
	// nonzero to trip the guard without pointing at real snapshot data.
	var hdr [12]byte
	binary.BigEndian.PutUint32(hdr[0:], 1)          // nb_snapshots = 1
	binary.BigEndian.PutUint64(hdr[4:], 0x10000)    // snapshots_offset (nonzero)
	if _, err := qw.f.WriteAt(hdr[:], 0x3C); err != nil {
		w.Close()
		t.Fatalf("poke header: %v", err)
	}
	if err := qw.Sync(); err != nil {
		w.Close()
		t.Fatalf("Sync: %v", err)
	}
	w.Close()

	if _, err := Compact(context.Background(), overlay); err == nil {
		t.Fatalf("Compact on image with internal snapshots: expected error, got nil")
	}
}

// TestCompact_RejectsZeroVirtualSize: an image whose header reports a zero
// virtual size must be rejected (nothing meaningful to compact; createQcow2
// never produces one, but a foreign/corrupt image could). We craft it by
// creating a valid image and then poking the size field (0x18) to 0.
func TestCompact_RejectsZeroVirtualSize(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "standalone.qcow2")
	if err := createQcow2(img, uint64(clusterSize), "", "", defaultOverlayOpt); err != nil {
		t.Fatalf("createQcow2: %v", err)
	}
	w := openWritable(t, img)
	qw := w.(*qcow2Writable)
	// virtual disk size at 0x18 (u64). Zero it.
	if _, err := qw.f.WriteAt(make([]byte, 8), 0x18); err != nil {
		w.Close()
		t.Fatalf("poke header: %v", err)
	}
	if err := qw.Sync(); err != nil {
		w.Close()
		t.Fatalf("Sync: %v", err)
	}
	w.Close()

	if _, err := Compact(context.Background(), img); err == nil {
		t.Fatalf("Compact on zero-virtual-size image: expected error, got nil")
	}
}

// TestQcow2_HeaderLength104 covers foreign images whose v3 header_length is
// the spec minimum 104 (e.g. written by qemu-img): header extensions then
// start at byte 104, not at our own qcow2HeaderLen (112). The parser must
// honor the stored header_length — with a fixed 112 start it would skip the
// first extension's magic/length, misread the length field as a magic, and
// reject the image with a spurious overflow error.
func TestQcow2_HeaderLength104(t *testing.T) {
	dir := t.TempDir()
	overlay, want := buildOverlayWithWrites(t, dir, []writeOp{
		{1, patterned(0x42, clusterSize)},
	})

	// Rewrite cluster 0 so the extension block starts at 104: move the
	// [112,bfOff) bytes (backing-format ext + end marker) down to 104 and
	// set header_length=104. The backing name stays at bfOff (the gap
	// between the end marker and the name is ignored by parsers).
	f, err := os.OpenFile(overlay, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open overlay: %v", err)
	}
	cluster0 := make([]byte, clusterSize)
	if _, err := f.ReadAt(cluster0, 0); err != nil {
		t.Fatalf("read cluster 0: %v", err)
	}
	bfOff := int(binary.BigEndian.Uint64(cluster0[0x08:]))
	ext := append([]byte(nil), cluster0[qcow2HeaderLen:bfOff]...)
	copy(cluster0[qcow2V3HeaderLen:], ext)
	clear(cluster0[qcow2V3HeaderLen+len(ext) : bfOff])
	binary.BigEndian.PutUint32(cluster0[0x64:], qcow2V3HeaderLen)
	if _, err := f.WriteAt(cluster0, 0); err != nil {
		t.Fatalf("rewrite cluster 0: %v", err)
	}
	f.Close()

	// Sanity: a backing-format extension really begins at 104 now.
	if m := binary.BigEndian.Uint32(cluster0[qcow2V3HeaderLen:]); m != extBackingFormat {
		t.Fatalf("extension magic at %d = %#x, want %#x", qcow2V3HeaderLen, m, extBackingFormat)
	}

	// Compact must parse the extension starting AT 104 and rebuild a valid
	// overlay preserving the guest view.
	if _, err := Compact(context.Background(), overlay); err != nil {
		t.Fatalf("Compact on header_length=104 image: %v", err)
	}
	assertView(t, overlay, want)

	// The rebuilt image (written by our own createQcow2) must still declare
	// the backing format "raw" in the extension at qcow2HeaderLen.
	rf, err := os.Open(overlay)
	if err != nil {
		t.Fatalf("open rebuilt overlay: %v", err)
	}
	defer rf.Close()
	buf := make([]byte, 256)
	if _, err := rf.ReadAt(buf, 0); err != nil {
		t.Fatalf("read rebuilt header: %v", err)
	}
	if m := binary.BigEndian.Uint32(buf[qcow2HeaderLen:]); m != extBackingFormat {
		t.Errorf("rebuilt extension magic = %#x, want %#x (backing format lost)", m, extBackingFormat)
	}
	if l := binary.BigEndian.Uint32(buf[qcow2HeaderLen+4:]); l != 3 {
		t.Errorf("rebuilt extension length = %d, want 3 (\"raw\")", l)
	} else if string(buf[qcow2HeaderLen+8:qcow2HeaderLen+11]) != "raw" {
		t.Errorf("rebuilt backing format = %q, want %q", buf[qcow2HeaderLen+8:qcow2HeaderLen+11], "raw")
	}
}

// TestQcow2_HeaderLengthInvalid rejects header_length below the fixed v3
// header (104): no extension can start before the header ends.
func TestQcow2_HeaderLengthInvalid(t *testing.T) {
	dir := t.TempDir()
	overlay, _ := buildOverlayWithWrites(t, dir, []writeOp{
		{1, patterned(0x42, clusterSize)},
	})
	f, err := os.OpenFile(overlay, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open overlay: %v", err)
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], 72) // < 104: impossible
	if _, err := f.WriteAt(b[:], 0x64); err != nil {
		t.Fatalf("forge header_length: %v", err)
	}
	f.Close()

	_, err = Compact(context.Background(), overlay)
	if err == nil {
		t.Fatal("Compact on header_length=72 image: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "header_length") {
		t.Errorf("error should mention header_length, got: %v", err)
	}
}
