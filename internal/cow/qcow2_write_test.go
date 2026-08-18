package cow

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// openWritable is a test helper.
func openWritable(t *testing.T, path string) WritableBackend {
	t.Helper()
	be, err := OpenWritable(path)
	if err != nil {
		t.Fatalf("OpenWritable(%s): %v", path, err)
	}
	// Close even if a later t.Fatalf exits the test early; explicit Close
	// calls in tests simply make the cleanup a no-op-ish second close.
	t.Cleanup(func() { be.Close() })
	return be
}

// TestQcow2Write_FullClusterShadows: a full-cluster guest write allocates a
// data cluster and shadows the backing entirely.
func TestQcow2Write_FullClusterShadows(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x11, 4*clusterSize))
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create: %v", err)
	}

	be := openWritable(t, overlay)
	defer be.Close()
	guest := patterned(0xE5, clusterSize)
	if _, err := be.WriteAt(guest, 3*clusterSize); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := be.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	dest := filepath.Join(dir, "out.raw")
	if err := CommitOverlay(context.Background(), overlay, dest); err != nil {
		t.Fatalf("convert: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if len(got) < 4*clusterSize {
		t.Fatalf("converted output too small: %d bytes, want >= %d", len(got), 4*clusterSize)
	}
	if !bytes.Equal(got[3*clusterSize:4*clusterSize], guest) {
		t.Error("cluster 3 should be guest data")
	}
	if !bytes.Equal(got[:clusterSize], patterned(0x11, 4*clusterSize)[:clusterSize]) {
		t.Error("cluster 0 should still come from backing")
	}
}

// TestQcow2Write_PartialClusterCoW: a 512-byte write into an unallocated
// cluster must preserve the rest of the backing cluster (copy-on-write).
func TestQcow2Write_PartialClusterCoW(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	baseData := patterned(0x42, 2*clusterSize)
	mustWriteRaw(t, base, 0, baseData)
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create: %v", err)
	}

	be := openWritable(t, overlay)
	defer be.Close()
	patch := patterned(0x99, 512)
	if _, err := be.WriteAt(patch, clusterSize+100); err != nil {
		t.Fatalf("partial write: %v", err)
	}

	dest := filepath.Join(dir, "out.raw")
	if err := CommitOverlay(context.Background(), overlay, dest); err != nil {
		t.Fatalf("convert: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	want := append([]byte{}, baseData...)
	copy(want[clusterSize+100:], patch)
	if !bytes.Equal(got, want) {
		t.Error("partial write did not CoW correctly (cluster should be backing + patch)")
	}
}

// TestQcow2Write_SecondL2Table: writes past the first L2 table's coverage
// (cluster >= 8192) must allocate a second L2 table transparently.
func TestQcow2Write_SecondL2Table(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	// Sparse 600 MiB base → l1Size = 2 (two L2 tables needed for full range).
	f, err := os.OpenFile(base, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("create base: %v", err)
	}
	if err := f.Truncate(600 << 20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create: %v", err)
	}
	be := openWritable(t, overlay)
	defer be.Close()
	data := patterned(0x77, clusterSize)
	// cluster 9000 lives in the second L2 table (first covers 0..8191).
	if _, err := be.WriteAt(data, 9000*clusterSize); err != nil {
		t.Fatalf("write at cluster 9000: %v", err)
	}

	// Read back through the chain reader.
	img, err := openGuestImage(overlay)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer img.Close()
	got := make([]byte, clusterSize)
	if _, err := img.ReadAt(got, 9000*clusterSize); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("cluster 9000 readback mismatch")
	}
}

// TestQcow2Write_DifferentialCheck writes via the Go backend and then lets
// the real qemu-img validate the result (refcounts included) when available.
func TestQcow2Write_DifferentialCheck(t *testing.T) {
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
	// Sparse 600 MiB base so the third write lands beyond the first L2 table.
	bf, err := os.OpenFile(base, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("create base: %v", err)
	}
	if err := bf.Truncate(600 << 20); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := bf.WriteAt(patterned(0x01, 4*clusterSize), 0); err != nil {
		t.Fatalf("seed base: %v", err)
	}
	bf.Close()
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create: %v", err)
	}
	be := openWritable(t, overlay)
	// Mix of full and partial writes, incl. beyond the first L2 table.
	if _, err := be.WriteAt(patterned(0x21, clusterSize), 2*clusterSize); err != nil {
		t.Fatalf("write1: %v", err)
	}
	if _, err := be.WriteAt(patterned(0x22, 1000), 3*clusterSize+55); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if _, err := be.WriteAt(patterned(0x23, clusterSize), 9000*clusterSize); err != nil {
		t.Fatalf("write3: %v", err)
	}
	if err := be.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	be.Close()

	// qemu-img check validates refcount consistency of our allocations.
	if out, err := exec.Command(qemuImg, "check", overlay).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img check rejected Go-written overlay: %v: %s", err, out)
	}

	// And its flatten must match ours byte-for-byte.
	goOut := filepath.Join(dir, "go.raw")
	if err := CommitOverlay(context.Background(), overlay, goOut); err != nil {
		t.Fatalf("go convert: %v", err)
	}
	qemuOut := filepath.Join(dir, "qemu.raw")
	if out, err := exec.Command(qemuImg, "convert", "-O", "raw", overlay, qemuOut).CombinedOutput(); err != nil {
		t.Fatalf("qemu convert: %v: %s", err, out)
	}
	g, err := os.ReadFile(goOut)
	if err != nil {
		t.Fatalf("read go convert output: %v", err)
	}
	q, err := os.ReadFile(qemuOut)
	if err != nil {
		t.Fatalf("read qemu convert output: %v", err)
	}
	if !bytes.Equal(g, q) {
		t.Errorf("convert mismatch after writes: go=%d qemu=%d bytes", len(g), len(q))
	}
}

// TestQcow2Write_RawPassthrough: a raw image gets direct writes, no CoW.
func TestQcow2Write_RawPassthrough(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	mustWriteRaw(t, img, 0, make([]byte, 2*clusterSize))
	be := openWritable(t, img)
	defer be.Close()
	data := patterned(0x5C, 4096)
	if _, err := be.WriteAt(data, 8192); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4096)
	if _, err := be.ReadAt(got, 8192); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("raw passthrough mismatch")
	}
}
