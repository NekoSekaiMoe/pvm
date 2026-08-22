package cow

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Malicious-header coverage: hostile qcow2 images must be rejected at open —
// backing cycles, runaway chains, absolute/traversing backing names, absurd
// virtual sizes. These tests craft minimal headers directly instead of going
// through createQcow2, simulating a foreign attacker-supplied image.

// craftHeader builds a minimal-but-parseable qcow2 v3 cluster 0 into buf
// (clusterSize bytes) and writes it to path. Parameters:
//
//	size       virtual size (header 0x18)
//	backing    backing file name stored verbatim ("" = standalone)
//	format     declared backing format extension ("", "raw", "qcow2")
func craftHeader(t *testing.T, path string, size uint64, backing, format string) {
	t.Helper()
	buf := make([]byte, clusterSize)
	copy(buf[0:4], qcow2Magic)
	binary.BigEndian.PutUint32(buf[0x04:], qcow2Version3)
	binary.BigEndian.PutUint32(buf[0x14:], clusterBits)
	binary.BigEndian.PutUint64(buf[0x18:], size)
	binary.BigEndian.PutUint32(buf[0x24:], 1)                   // l1_size
	binary.BigEndian.PutUint64(buf[0x28:], uint64(clusterSize)) // l1_offset
	binary.BigEndian.PutUint32(buf[0x60:], refcountOrder)
	binary.BigEndian.PutUint32(buf[0x64:], qcow2HeaderLen)

	off := uint64(qcow2HeaderLen)
	if format != "" {
		binary.BigEndian.PutUint32(buf[off:], extBackingFormat)
		binary.BigEndian.PutUint32(buf[off+4:], uint32(len(format)))
		copy(buf[off+8:], format)
		off += 8 + roundUp8(uint64(len(format)))
	}
	off += 8 // end-of-extensions marker (already zeroed)
	if backing != "" {
		if off+uint64(len(backing)) > clusterSize {
			t.Fatalf("craftHeader: backing %q too long", backing)
		}
		binary.BigEndian.PutUint64(buf[0x08:], off)
		binary.BigEndian.PutUint32(buf[0x10:], uint32(len(backing)))
		copy(buf[off:], backing)
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// Append the (all-zero) L1 table cluster the header points at: l1_offset
	// is clusterSize, so a structurally valid crafted image needs a second
	// cluster. A zero L1 entry means "unallocated" — reads fall through to
	// the backing chain, which is exactly what these tests exercise.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.Write(make([]byte, clusterSize)); err != nil {
		t.Fatalf("append L1 cluster to %s: %v", path, err)
	}
}

func TestOpen_RejectsBackingCycle(t *testing.T) {
	dir := t.TempDir()
	RegisterBackingRoot(dir)
	defer UnregisterBackingRoot(dir)
	a := filepath.Join(dir, "a.qcow2")
	b := filepath.Join(dir, "b.qcow2")
	craftHeader(t, a, clusterSize, b, "")
	craftHeader(t, b, clusterSize, a, "")
	_, err := openGuestImage(a)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle detection, got: %v", err)
	}
}

func TestOpen_RejectsSelfBackingCycle(t *testing.T) {
	dir := t.TempDir()
	RegisterBackingRoot(dir)
	defer UnregisterBackingRoot(dir)
	a := filepath.Join(dir, "self.qcow2")
	craftHeader(t, a, clusterSize, a, "")
	_, err := openGuestImage(a)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle detection, got: %v", err)
	}
}

func TestOpen_RejectsChainDeeperThanLimit(t *testing.T) {
	dir := t.TempDir()
	RegisterBackingRoot(dir)
	defer UnregisterBackingRoot(dir)
	const depth = maxBackingChainDepth + 10
	names := make([]string, depth)
	for i := range names {
		names[i] = filepath.Join(dir, fmt.Sprintf("link%02d.qcow2", i))
	}
	// Deepest link is plain raw; everything above points one level down.
	if err := os.WriteFile(names[depth-1], []byte("raw"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := depth - 2; i >= 0; i-- {
		craftHeader(t, names[i], clusterSize, names[i+1], "")
	}
	_, err := openGuestImage(names[0])
	if err == nil || !strings.Contains(err.Error(), "backing chain deeper") {
		t.Fatalf("expected depth-limit rejection, got: %v", err)
	}
}

func TestOpen_RejectsAbsoluteBackingOutsideRoots(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir() // NOT registered as an allowed root
	img := filepath.Join(dir, "overlay.qcow2")
	target := filepath.Join(outside, "secret.img")
	if err := os.WriteFile(target, make([]byte, clusterSize), 0644); err != nil {
		t.Fatal(err)
	}
	craftHeader(t, img, clusterSize, target, "")
	_, err := openGuestImage(img)
	if err == nil || !strings.Contains(err.Error(), "managed storage roots") {
		t.Fatalf("expected backing-root rejection, got: %v", err)
	}
}

func TestOpen_RejectsSystemFileBacking(t *testing.T) {
	dir := t.TempDir()
	RegisterBackingRoot(dir)
	defer UnregisterBackingRoot(dir)
	img := filepath.Join(dir, "overlay.qcow2")
	craftHeader(t, img, clusterSize, "/etc/hostname", "")
	_, err := openGuestImage(img)
	if err == nil || !strings.Contains(err.Error(), "managed storage roots") {
		t.Fatalf("expected backing-root rejection, got: %v", err)
	}
}

func TestOpen_RejectsRelativeBackingTraversal(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	RegisterBackingRoot(sub)
	defer UnregisterBackingRoot(sub)
	img := filepath.Join(sub, "overlay.qcow2")
	// Resolves to dir/escape.img — outside sub AND outside every registered
	// root (only sub itself is registered).
	esc := filepath.Join(dir, "escape.img")
	if err := os.WriteFile(esc, make([]byte, clusterSize), 0644); err != nil {
		t.Fatal(err)
	}
	craftHeader(t, img, clusterSize, "../escape.img", "")
	_, err := openGuestImage(img)
	if err == nil || !strings.Contains(err.Error(), "managed storage roots") {
		t.Fatalf("expected backing-root rejection, got: %v", err)
	}
}

func TestOpen_AcceptsSiblingRelativeBacking(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.raw")
	view := patterned(0x5a, clusterSize)
	mustWriteRaw(t, base, 0, view)
	img := filepath.Join(dir, "overlay.qcow2")
	craftHeader(t, img, clusterSize, "base.raw", "raw")
	got := make([]byte, clusterSize)
	if _, err := readFull(t, img, got); err != nil {
		t.Fatalf("open/read: %v", err)
	}
	for i := range got {
		if got[i] != view[i] {
			t.Fatalf("byte %d differs through backing chain", i)
		}
	}
}

func readFull(t *testing.T, path string, buf []byte) (int, error) {
	t.Helper()
	img, err := openGuestImage(path)
	if err != nil {
		return 0, err
	}
	defer img.Close()
	n, err := img.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, err
	}
	return n, nil
}

func TestOpen_RejectsOversizedVirtualSize(t *testing.T) {
	dir := t.TempDir()
	RegisterBackingRoot(dir)
	defer UnregisterBackingRoot(dir)
	img := filepath.Join(dir, "huge.qcow2")
	craftHeader(t, img, maxVirtualSize+clusterSize, "", "")
	_, err := openGuestImage(img)
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("expected virtual-size cap rejection, got: %v", err)
	}
}

func TestDivCeil(t *testing.T) {
	// A zero divisor must be an error, never a panic.
	if _, err := divCeil(10, 0); err == nil {
		t.Fatal("divCeil(10, 0) should reject a zero divisor")
	}
	// Non-exact ceiling division near the uint64 limit: the naive
	// (a+b-1)/b wraps here; the overflow-safe path must return the exact
	// ceiling 2^64/3.
	got, err := divCeil(^uint64(0)-1, 3)
	if err != nil {
		t.Fatalf("divCeil(^uint64(0)-1, 3): %v", err)
	}
	if want := ^uint64(0) / 3; got != want {
		t.Fatalf("divCeil(^uint64(0)-1, 3) = %d, want %d", got, want)
	}
	// Exact division at the uint64 max succeeds (no spurious overflow).
	if got, err = divCeil(^uint64(0), 1); err != nil || got != ^uint64(0) {
		t.Fatalf("divCeil(^uint64(0), 1) = %d, %v; want %d, nil", got, err, ^uint64(0))
	}
	// Ordinary anchors: ceiling for inexact, identity for exact.
	if got, err = divCeil(10, 4); err != nil || got != 3 {
		t.Fatalf("divCeil(10, 4) = %d, %v; want 3, nil", got, err)
	}
	if got, err = divCeil(8, 4); err != nil || got != 2 {
		t.Fatalf("divCeil(8, 4) = %d, %v; want 2, nil", got, err)
	}
}

// TestBackingRoots_LifecycleScoped verifies that overlay-authorized backing
// roots end with the overlay that authorized them instead of lingering for
// the life of the process, and that a shared base dir stays authorized until
// the LAST overlay using it is removed.
func TestBackingRoots_LifecycleScoped(t *testing.T) {
	baseDir := t.TempDir()
	// A different tree: only the overlay-scoped registration (or a manual
	// one) can authorize baseDir.
	overlayDir := t.TempDir()
	base := filepath.Join(baseDir, "base.raw")
	mustWriteRaw(t, base, 0, patterned(0x5a, clusterSize))

	// probe asserts whether baseDir currently authorizes backing opens.
	// The probe image lives in overlayDir, so its own directory never
	// covers baseDir.
	probe := func() error {
		p := filepath.Join(overlayDir, "probe.qcow2")
		craftHeader(t, p, clusterSize, base, "raw")
		_, err := openGuestImage(p)
		return err
	}

	overlay := filepath.Join(overlayDir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	if err := probe(); err != nil {
		t.Fatalf("backing root should be authorized while the overlay lives: %v", err)
	}

	// A second overlay over the same base keeps the root alive after the
	// first is removed (refcounted, not dropped early).
	overlay2 := filepath.Join(overlayDir, "ov2.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay2); err != nil {
		t.Fatalf("CreateOverlay (2nd): %v", err)
	}
	if err := RemoveOverlay(overlay); err != nil {
		t.Fatalf("RemoveOverlay: %v", err)
	}
	if err := probe(); err != nil {
		t.Fatalf("backing root must survive while another overlay uses it: %v", err)
	}

	// Last association gone -> the root is gone too.
	if err := RemoveOverlay(overlay2); err != nil {
		t.Fatalf("RemoveOverlay (2nd): %v", err)
	}
	if err := probe(); err == nil || !strings.Contains(err.Error(), "managed storage roots") {
		t.Fatalf("expected backing-root rejection after the last overlay was removed, got: %v", err)
	}
}

// TestBackingRoots_RecreateDropsStaleRoot verifies that replacing a stale
// overlay (same path, different base) ends the OLD base dir's authorization
// while keeping the new one.
func TestBackingRoots_RecreateDropsStaleRoot(t *testing.T) {
	baseDir1 := t.TempDir()
	baseDir2 := t.TempDir()
	overlayDir := t.TempDir()
	base1 := filepath.Join(baseDir1, "base.raw")
	base2 := filepath.Join(baseDir2, "base.raw")
	mustWriteRaw(t, base1, 0, patterned(0x11, clusterSize))
	mustWriteRaw(t, base2, 0, patterned(0x22, clusterSize))

	// probeWith asserts whether base is currently an authorized backing.
	probeWith := func(base string) error {
		p := filepath.Join(overlayDir, "probe.qcow2")
		craftHeader(t, p, clusterSize, base, "raw")
		_, err := openGuestImage(p)
		return err
	}

	overlay := filepath.Join(overlayDir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base1, overlay); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	// Recreate at the same path over the other base: the stale overlay is
	// destroyed, and baseDir1's authorization must end with it.
	if err := CreateOverlay(context.Background(), base2, overlay); err != nil {
		t.Fatalf("CreateOverlay (recreate): %v", err)
	}
	if err := probeWith(base1); err == nil || !strings.Contains(err.Error(), "managed storage roots") {
		t.Fatalf("expected the replaced base dir to be deauthorized, got: %v", err)
	}
	// The new base dir, by contrast, stays authorized...
	if err := probeWith(base2); err != nil {
		t.Fatalf("recreated overlay's base dir should stay authorized: %v", err)
	}
	// ...until the recreated overlay itself is removed.
	if err := RemoveOverlay(overlay); err != nil {
		t.Fatalf("RemoveOverlay: %v", err)
	}
	if err := probeWith(base2); err == nil || !strings.Contains(err.Error(), "managed storage roots") {
		t.Fatalf("expected deauthorization after RemoveOverlay, got: %v", err)
	}
}

func TestComputeQcow2Layout_OverflowSafe(t *testing.T) {
	for _, size := range []uint64{
		^uint64(0),
		^uint64(0) - clusterSize,
		^uint64(0) - clusterSize + 2, // classic ceil-div wraparound point
		maxVirtualSize + 1,
	} {
		if _, err := computeQcow2Layout(size, clusterBits, false); err == nil {
			t.Fatalf("computeQcow2Layout(%d) accepted a hostile size", size)
		}
	}
	// Sanity: legal sizes still work.
	if _, err := computeQcow2Layout(maxVirtualSize, clusterBits, false); err != nil {
		t.Fatalf("16 TiB layout should be computable: %v", err)
	}
}

func TestConvertToRaw_MirrorsSourceMode(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	if err := createQcow2(src, 1<<20, "", "", defaultOverlayOpt); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.Chmod(src, 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.raw")
	if err := convertToRaw(context.Background(), src, dst); err != nil {
		t.Fatalf("convertToRaw: %v", err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("converted raw mode = %v, want 0600 (source mode mirrored)", fi.Mode().Perm())
	}
}

func TestConvertToQcow2_NonClusterAlignedRawSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "unaligned.raw")
	// 3 full clusters plus a 100-byte tail: exercises the tail-clamp path.
	size := int64(3*clusterSize + 100)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(0x30 + i%97)
	}
	data[clusterSize] = 0 // one all-zero cluster in the middle stays sparse
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.qcow2")
	if err := ConvertToQcow2(context.Background(), src, dst, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2: %v", err)
	}
	img, err := openGuestImage(dst)
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}
	defer img.Close()
	if img.Size() != uint64(size) {
		t.Fatalf("dest virtual size = %d, want %d (source bytes preserved)", img.Size(), size)
	}
	got := make([]byte, size)
	if _, err := img.ReadAt(got, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read dest: %v", err)
	}
	for i := range got {
		if got[i] != data[i] {
			t.Fatalf("dest byte %d = %#x, want %#x", i, got[i], data[i])
		}
	}
}
