package cow

// Regression tests for header-extension / backing-name parsing of foreign
// (qemu-img-style) qcow2 images: standalone images with header_length 104
// whose extensions live after the fixed header, and forged backing-name
// offsets/sizes that must be rejected instead of read past cluster 0.

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// forgeCluster0 applies fn to cluster 0 of the image at path and writes it
// back. Tests use it to hand-craft foreign or malformed headers.
func forgeCluster0(t *testing.T, path string, fn func(cluster0 []byte)) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	cluster0 := make([]byte, clusterSize)
	if _, err := f.ReadAt(cluster0, 0); err != nil {
		f.Close()
		t.Fatalf("read cluster 0 of %s: %v", path, err)
	}
	fn(cluster0)
	if _, err := f.WriteAt(cluster0, 0); err != nil {
		f.Close()
		t.Fatalf("rewrite cluster 0 of %s: %v", path, err)
	}
	f.Close()
}

// TestQcow2StandaloneHeaderLength104WithExtensions: a STANDALONE image
// (bfOff == 0) whose header_length is the spec minimum 104 — as qemu-img
// writes — with extensions starting at byte 104. The parser must scan them
// through cluster 0 and honor the declared backing format; previously the
// scan was capped at header_length, so the extension was silently skipped
// (or misparsed as overflowing).
func TestQcow2StandaloneHeaderLength104WithExtensions(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.img")
	mustWriteRaw(t, src, 0, patterned(0x41, 4*clusterSize))
	img := filepath.Join(dir, "standalone.qcow2")
	if err := ConvertToQcow2(context.Background(), src, img, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2: %v", err)
	}

	// Rebuild cluster 0 as a foreign writer would: header_length=104, a
	// backing-format extension ("raw") at 104, an end-of-extensions marker
	// after it, and no backing name (bfOff/bfSize zeroed). The rest of
	// cluster 0 is zero, as qemu-img leaves it.
	forgeCluster0(t, img, func(c0 []byte) {
		clear(c0[qcow2V3HeaderLen:])
		binary.BigEndian.PutUint32(c0[qcow2V3HeaderLen:], extBackingFormat)
		binary.BigEndian.PutUint32(c0[qcow2V3HeaderLen+4:], 3)
		copy(c0[qcow2V3HeaderLen+8:], "raw\x00\x00\x00\x00\x00")
		binary.BigEndian.PutUint32(c0[qcow2V3HeaderLen+16:], 0) // end-of-extensions marker
		binary.BigEndian.PutUint32(c0[0x64:], qcow2V3HeaderLen) // header_length = 104
		binary.BigEndian.PutUint64(c0[0x08:], 0)                // no backing name
		binary.BigEndian.PutUint32(c0[0x10:], 0)
	})

	parsed, err := openGuestImage(img)
	if err != nil {
		t.Fatalf("open standalone image with header_length=104: %v", err)
	}
	defer parsed.Close()
	q := parsed.(*qcow2Image)
	if q.backing != nil {
		t.Fatalf("standalone image must not open a backing, got %s", q.backingAbs)
	}
	if q.backingFormat != "raw" {
		t.Errorf("extension at 104 not parsed: backingFormat = %q, want %q", q.backingFormat, "raw")
	}

	// The guest view must survive the foreign header unchanged.
	assertGuestView(t, img, patterned(0x41, 4*clusterSize))
}

// TestQcow2StandaloneMissingEndMarker: a standalone image whose extension
// region runs to the end of cluster 0 without a 0-magic end-of-extensions
// marker is malformed and must be rejected, not silently accepted with
// unknown extensions ignored.
func TestQcow2StandaloneMissingEndMarker(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.img")
	mustWriteRaw(t, src, 0, patterned(0x42, 4*clusterSize))
	img := filepath.Join(dir, "nomarker.qcow2")
	if err := ConvertToQcow2(context.Background(), src, img, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2: %v", err)
	}

	// Same forge as the 104 test but WITHOUT the end marker: one extension
	// at 104 and then zeros-free filler... zeros ARE the marker (magic 0 at
	// e+8<=extEnd), so to test the missing-marker path the region must be
	// filled with nonzero extension headers until the cluster boundary.
	forgeCluster0(t, img, func(c0 []byte) {
		clear(c0[qcow2V3HeaderLen:])
		binary.BigEndian.PutUint32(c0[0x64:], qcow2V3HeaderLen)
		binary.BigEndian.PutUint64(c0[0x08:], 0)
		binary.BigEndian.PutUint32(c0[0x10:], 0)
		// Fill [104, clusterSize) with a repeating fake extension header
		// (nonzero magic, length 0) so the scan never meets magic 0.
		for off := qcow2V3HeaderLen; off+8 <= clusterSize; off += 8 {
			binary.BigEndian.PutUint32(c0[off:], 0xdeadbeef)
			binary.BigEndian.PutUint32(c0[off+4:], 0)
		}
	})

	_, err := openGuestImage(img)
	if err == nil {
		t.Fatal("open standalone image without end-of-extensions marker: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "end-of-extensions") {
		t.Errorf("error should mention end-of-extensions marker, got: %v", err)
	}
}

// TestQcow2BackingNameRegionOutOfBounds: the backing name must lie entirely
// inside cluster 0. Forged offsets/sizes that cross the cluster boundary (or
// point before the header) must be rejected at open time — previously the
// name was read from whatever followed cluster 0 (L1/refcount metadata or
// attacker-chosen data) and parsed as a path.
func TestQcow2BackingNameRegionOutOfBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bfOff  uint64
		bfSize uint32
	}{
		{"crosses_cluster0", clusterSize - 2, 16},     // straddles the boundary
		{"beyond_cluster0", 2 * clusterSize, 8},       // wholly outside
		{"before_header", 32, 8},                      // inside the fixed header
		{"end_at_cluster_edge", clusterSize - 8, 8},   // bfOff+bfSize == clusterSize: allowed
		{"end_past_cluster_edge", clusterSize - 4, 9}, // bfOff+bfSize > clusterSize: rejected
	} {
		wantErr := tc.bfOff < qcow2V3HeaderLen || tc.bfOff > clusterSize || uint64(tc.bfSize) > clusterSize-tc.bfOff
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "base.img")
			mustWriteRaw(t, base, 0, patterned(0x31, clusterSize))
			overlay := filepath.Join(dir, "ov.qcow2")
			if err := CreateOverlay(context.Background(), base, overlay); err != nil {
				t.Fatalf("CreateOverlay: %v", err)
			}
			forgeCluster0(t, overlay, func(c0 []byte) {
				binary.BigEndian.PutUint64(c0[0x08:], tc.bfOff)
				binary.BigEndian.PutUint32(c0[0x10:], tc.bfSize)
				if !wantErr {
					// In-bounds regions must carry a REAL backing name that
					// fits exactly in [bfOff, bfOff+bfSize), so the allowed
					// boundary case exercises the successful open path
					// (zero bytes would fail backing resolution instead of
					// the boundary check under test).
					copy(c0[tc.bfOff:], "base.img")
				}
			})

			img, err := openGuestImage(overlay)
			if wantErr && err == nil {
				t.Fatalf("bfOff=%#x bfSize=%d: expected rejection, got nil (backing name read out of bounds)", tc.bfOff, tc.bfSize)
			}
			if !wantErr {
				if err != nil {
					t.Fatalf("bfOff=%#x bfSize=%d: valid region rejected: %v", tc.bfOff, tc.bfSize, err)
				}
				// The in-bounds name resolved a live chain; assert it and
				// close so the test never leaks the overlay+backing fds.
				q, ok := img.(*qcow2Image)
				if !ok {
					t.Fatalf("openGuestImage returned %T, want *qcow2Image", img)
				}
				if q.backing == nil || !strings.HasSuffix(q.backingAbs, "base.img") {
					t.Errorf("bfOff=%#x bfSize=%d: backing not resolved (backing=%v backingAbs=%q)", tc.bfOff, tc.bfSize, q.backing != nil, q.backingAbs)
				}
				if err := img.Close(); err != nil {
					t.Errorf("close opened image: %v", err)
				}
				return
			}
			// Cases the older extension-region checks already catch are rejected
			// with their own message; only boundary-straddling regions reach the
			// new backing-name check.
			if err != nil && tc.bfOff >= qcow2V3HeaderLen && tc.bfOff <= clusterSize && !strings.Contains(err.Error(), "invalid backing name region") {
				t.Errorf("bfOff=%#x bfSize=%d: error should mention invalid backing name region, got: %v", tc.bfOff, tc.bfSize, err)
			}
		})
	}
}

// TestConvertDestModeMirrorsSource: ConvertToQcow2's result must carry the
// source's permission bits, not the 0600 that os.CreateTemp gives the temp
// file (rename preserves it). Mirrors Compact's existing mode-alignment.
func TestConvertDestModeMirrorsSource(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x33, 2*clusterSize))
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	w := openWritable(t, overlay)
	if _, err := w.WriteAt(patterned(0x51, clusterSize), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	w.Close()

	for _, mode := range []os.FileMode{0600, 0640, 0644} {
		if err := os.Chmod(overlay, mode); err != nil {
			t.Fatalf("chmod source %o: %v", mode, err)
		}
		dst := filepath.Join(dir, "conv-"+mode.String()+".qcow2")
		if err := ConvertToQcow2(context.Background(), overlay, dst, ConvertDefaultOpt); err != nil {
			t.Fatalf("ConvertToQcow2 (source %o): %v", mode, err)
		}
		st, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("stat dest: %v", err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("source %o: dest mode = %o, want %o (CreateTemp 0600 leaked through rename?)", mode, st.Mode().Perm(), mode)
		}
	}
}

// TestConvertDestModeSurvivesSourcePathUnlink: the mode captured for the
// chmod must come from the OPEN source descriptor, not a post-copy
// os.Stat(srcPath). A symlink source unlinked (or replaced) mid-convert
// keeps the conversion alive via its open fd, but the late path stat would
// fail — previously the chmod was then silently skipped and the dest leaked
// os.CreateTemp's 0600 through the rename.
func TestConvertDestModeSurvivesSourcePathUnlink(t *testing.T) {
	dir := t.TempDir()
	// A deep overlay chain so the copy loop runs long enough for the
	// unlink to land strictly between openGuestImage and the final chmod.
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x41, clusterSize))
	prev := base
	for i := 0; i < 30; i++ {
		ov := filepath.Join(dir, fmt.Sprintf("ov%d.qcow2", i))
		if err := CreateOverlay(context.Background(), prev, ov); err != nil {
			t.Fatalf("CreateOverlay %d: %v", i, err)
		}
		if err := os.Chmod(ov, 0644); err != nil {
			t.Fatal(err)
		}
		prev = ov
	}
	link := filepath.Join(dir, "link.qcow2")
	if err := os.Symlink(prev, link); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(2 * time.Millisecond)
		os.Remove(link) // open fd survives; only the path stat breaks
	}()
	dst := filepath.Join(dir, "dst.qcow2")
	if err := ConvertToQcow2(context.Background(), link, dst, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2 via open fd: %v", err)
	}
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0644 {
		t.Errorf("dest mode = %o, want 0644 (post-copy os.Stat(src) silently skipped the chmod?)", st.Mode().Perm())
	}
}

// TestQcow2StandaloneTruncatedExtensionRegion: a standalone image whose file
// ends before the cluster-0 extension region it declares must be rejected.
// Previously the extension ReadAt tolerated io.EOF and scanned the zero
// filled tail, where zeros parse as an end-of-extensions marker — silently
// accepting a truncated (or hand-crafted undersized) image as well-formed.
func TestQcow2StandaloneTruncatedExtensionRegion(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.img")
	mustWriteRaw(t, src, 0, patterned(0x43, 4*clusterSize))
	img := filepath.Join(dir, "trunc.qcow2")
	if err := ConvertToQcow2(context.Background(), src, img, ConvertDefaultOpt); err != nil {
		t.Fatalf("ConvertToQcow2: %v", err)
	}
	// Rebuild cluster 0 as a foreign standalone image (bfOff=0 ⇒ extension
	// region runs to clusterSize), then TRUNCATE the file mid-cluster so the
	// region extends past EOF.
	forgeCluster0(t, img, func(c0 []byte) {
		clear(c0[qcow2V3HeaderLen:])
		binary.BigEndian.PutUint32(c0[0x64:], qcow2V3HeaderLen)
		binary.BigEndian.PutUint64(c0[0x08:], 0) // no backing name
		binary.BigEndian.PutUint32(c0[0x10:], 0)
	})
	if err := os.Truncate(img, int64(clusterSize/2)); err != nil {
		t.Fatal(err)
	}

	_, err := openGuestImage(img)
	if err == nil {
		t.Fatal("open image with truncated extension region: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "read header extensions") {
		t.Errorf("error should come from the extension read, got: %v", err)
	}
}
