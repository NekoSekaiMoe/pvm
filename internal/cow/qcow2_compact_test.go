package cow

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
	// Sparse nonzero backing: every byte = pattern, so a dropped cluster
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
	if err != nil && err.Error() != "EOF" {
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
	}
}

// TestCompact_PreservesContent covers the core semantics across the write
// patterns that matter: data writes, explicit zeros over nonzero backing,
// untouched (backing-read-through) clusters, and a far cluster forcing a
// second L2 table.
func TestCompact_PreservesContent(t *testing.T) {
	dir := t.TempDir()
	zeroCluster := make([]byte, clusterSize) // explicit zeros
	ops := []writeOp{
		{0, patterned(0x77, clusterSize)},   // data cluster, first L2 table
		{5, zeroCluster},                    // ZERO cluster shadowing nonzero backing
		{513, patterned(0x33, clusterSize)}, // data cluster, second L2 table
		{514, zeroCluster},                  // ZERO cluster in the second L2 table
	}
	overlay, want := buildOverlayWithWrites(t, dir, ops)

	st0, _ := os.Stat(overlay)
	stats, err := Compact(context.Background(), overlay)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	st1, _ := os.Stat(overlay)
	t.Logf("before=%d after=%d stats=%+v", st0.Size(), st1.Size(), stats)

	assertView(t, overlay, want)

	if stats.ClustersCopied != 2 {
		t.Errorf("ClustersCopied = %d, want 2", stats.ClustersCopied)
	}
	if stats.ClustersZeroed != 2 {
		t.Errorf("ClustersZeroed = %d, want 2", stats.ClustersZeroed)
	}
	if st1.Size() >= st0.Size() {
		t.Errorf("size did not shrink: before=%d after=%d", st0.Size(), st1.Size())
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
	if _, err := img.ReadAt(got, int64(10)*int64(clusterSize)); err != nil && err.Error() != "EOF" {
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
	// Build a standalone qcow2 by creating an overlay with no backing, then
	// writing some clusters. createQcow2 rejects empty backing? No: it writes
	// a standalone image when backingPath == "".
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
