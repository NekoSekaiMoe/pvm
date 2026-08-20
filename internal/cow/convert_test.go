package cow

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Round-trip the guest view through raw -> qcow2 -> raw and assert the bytes
// match at every step. Exercises both ConvertToQcow2 and ConvertToRaw, and
// proves ConvertToQcow2 preserves content (including zero regions, which must
// read back as zero rather than resurrect undefined bytes).
func TestConvert_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	// 4 MiB raw source with a sparse nonzero pattern: some clusters filled,
	// some left zero (so the qcow2 dest has holes to drop).
	const sz = 4 * 1024 * 1024
	cs := uint64(clusterSize)
	want := make([]byte, sz)
	// cluster 0: nonzero; 1: zero; 2: nonzero; 3-5: zero; 6: nonzero; rest zero.
	for _, c := range []int{0, 2, 6} {
		p := patterned(0x10+byte(c), int(cs))
		copy(want[c*int(cs):], p)
	}
	raw := filepath.Join(dir, "src.img")
	mustWriteRaw(t, raw, 0, want)

	qcow2 := filepath.Join(dir, "mid.qcow2")
	if err := ConvertToQcow2(context.Background(), raw, qcow2, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2: %v", err)
	}
	// dest must be qcow2.
	if !isQcow2(qcow2) {
		t.Fatalf("dest is not qcow2 (magic mismatch)")
	}
	// qcow2 must read back identical to the source.
	assertGuestView(t, qcow2, want)

	// Flatten back to raw and check again.
	raw2 := filepath.Join(dir, "out.img")
	if err := ConvertToRaw(context.Background(), qcow2, raw2); err != nil {
		t.Fatalf("ConvertToRaw: %v", err)
	}
	assertGuestView(t, raw2, want)

	// A second ConvertToQcow2 of the flattened raw must also match.
	qcow2b := filepath.Join(dir, "mid2.qcow2")
	if err := ConvertToQcow2(context.Background(), raw2, qcow2b, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2 2: %v", err)
	}
	assertGuestView(t, qcow2b, want)
}

// ConvertToQcow2 must shrink a sparse source (zero clusters dropped to
// unallocated).
func TestConvert_Qcow2IsSmallerForSparseSource(t *testing.T) {
	dir := t.TempDir()
	const sz = 4 * 1024 * 1024
	// Only 1 cluster of data, rest zero.
	raw := filepath.Join(dir, "src.img")
	mustWriteRaw(t, raw, 0, patterned(0x77, clusterSize))
	// Extend file to full size with zeros (sparse).
	f, err := os.OpenFile(raw, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := f.Truncate(int64(sz)); err != nil {
		f.Close()
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	qcow2 := filepath.Join(dir, "out.qcow2")
	if err := ConvertToQcow2(context.Background(), raw, qcow2, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2: %v", err)
	}
	st, _ := os.Stat(qcow2)
	// The qcow2 should be far smaller than the 4 MiB raw source: only the
	// header + metadata + 1 data cluster. Allow generous headroom for the
	// worst-case refblock region.
	if st.Size() > int64(2*1024*1024) {
		t.Errorf("qcow2 dest unexpectedly large: %d bytes (expected < 2 MiB for 1 data cluster)", st.Size())
	}
}

// ConvertToQcow2 of a layered overlay flattens the backing chain into a
// standalone image (like `qemu-img convert` with no -B).
func TestConvert_FlattensLayeredOverlay(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	virtual := uint64(2 * 1024 * 1024)
	baseView := make([]byte, virtual)
	for i := range baseView {
		baseView[i] = byte(0x20 + i%251)
	}
	mustWriteRaw(t, base, 0, baseView)

	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	w := openWritable(t, overlay)
	// Shadow cluster 3 with different data; zero cluster 7 over nonzero backing.
	shadow := patterned(0xAB, clusterSize)
	if _, err := w.WriteAt(shadow, int64(3)*int64(clusterSize)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if _, err := w.WriteAt(make([]byte, clusterSize), int64(7)*int64(clusterSize)); err != nil {
		t.Fatalf("WriteAt zero: %v", err)
	}
	w.Sync()
	w.Close()

	// Expected flattened view: base with cluster 3 shadowed, cluster 7 zeroed.
	want := make([]byte, virtual)
	copy(want, baseView)
	copy(want[3*clusterSize:], shadow)
	for i := 7 * clusterSize; i < 8*clusterSize; i++ {
		want[i] = 0
	}

	flat := filepath.Join(dir, "flat.qcow2")
	if err := ConvertToQcow2(context.Background(), overlay, flat, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2 of overlay: %v", err)
	}
	assertGuestView(t, flat, want)
}

// ConvertToRaw of a raw source is effectively a sparse copy.
func TestConvert_RawToRaw(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.img")
	mustWriteRaw(t, src, 0, patterned(0x33, 3*clusterSize))
	dst := filepath.Join(dir, "dst.img")
	if err := ConvertToRaw(context.Background(), src, dst); err != nil {
		t.Fatalf("ConvertToRaw: %v", err)
	}
	assertGuestView(t, dst, patterned(0x33, 3*clusterSize))
}

func assertGuestView(t *testing.T, path string, want []byte) {
	t.Helper()
	img := openGuestImageFile(t, path)
	defer img.Close()
	got := make([]byte, len(want))
	n, err := img.ReadAt(got, 0)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("ReadAt %s: %v", path, err)
	}
	if !bytes.Equal(got[:n], want[:n]) {
		for i := 0; i < n; i++ {
			if got[i] != want[i] {
				t.Fatalf("%s view differs at byte %d (cluster %d): got %#x want %#x",
					path, i, i/clusterSize, got[i], want[i])
			}
		}
	}
}

func TestSniffFormat(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "r.img")
	mustWriteRaw(t, raw, 0, patterned(0x01, 1024))
	if got := SniffFormat(raw); got != "raw" {
		t.Errorf("SniffFormat(raw) = %q, want raw", got)
	}
	q := filepath.Join(dir, "o.qcow2")
	if err := CreateOverlay(context.Background(), raw, q); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	if got := SniffFormat(q); got != "qcow2" {
		t.Errorf("SniffFormat(qcow2) = %q, want qcow2", got)
	}
}
