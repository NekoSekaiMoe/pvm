package cow

import (
	"bytes"
	"context"
	"errors"
	"io"
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

	// Stage outputs along the round-trip; each stage is a t.Run scenario so a
	// failure localizes which conversion direction broke, while sharing the
	// single `want` guest view across all of them.
	qcow2 := filepath.Join(dir, "mid.qcow2")
	raw2 := filepath.Join(dir, "out.img")
	qcow2b := filepath.Join(dir, "mid2.qcow2")

	stages := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			"raw_to_qcow2",
			func(t *testing.T) {
				if err := ConvertToQcow2(context.Background(), raw, qcow2, ConvertDefaultOpt); err != nil {
					t.Fatalf("ConvertToQcow2: %v", err)
				}
				if !isQcow2(qcow2) {
					t.Fatalf("dest is not qcow2 (magic mismatch)")
				}
				assertGuestView(t, qcow2, want)
			},
		},
		{
			"qcow2_to_raw",
			func(t *testing.T) {
				if err := ConvertToRaw(context.Background(), qcow2, raw2); err != nil {
					t.Fatalf("ConvertToRaw: %v", err)
				}
				assertGuestView(t, raw2, want)
			},
		},
		{
			"raw_to_qcow2_again",
			func(t *testing.T) {
				if err := ConvertToQcow2(context.Background(), raw2, qcow2b, ConvertDefaultOpt); err != nil {
					t.Fatalf("ConvertToQcow2 2: %v", err)
				}
				assertGuestView(t, qcow2b, want)
			},
		},
	}
	for _, st := range stages {
		t.Run(st.name, st.run)
	}
}

// ConvertToQcow2 must shrink a sparse source (zero clusters dropped to
// unallocated).
func TestConvert_Qcow2IsSmallerForSparseSource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dataLen int // nonzero data clusters at the start of a 4 MiB sparse raw
		maxSize int64
	}{
		{"one_cluster", 1, 2 * 1024 * 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			const sz = 4 * 1024 * 1024
			raw := filepath.Join(dir, "src.img")
			mustWriteRaw(t, raw, 0, patterned(0x77, tc.dataLen*clusterSize))
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
			// header + metadata + data clusters. Allow generous headroom for the
			// worst-case refblock region.
			if st.Size() > tc.maxSize {
				t.Errorf("qcow2 dest unexpectedly large: %d bytes (expected < %d for %d data cluster(s))", st.Size(), tc.maxSize, tc.dataLen)
			}
		})
	}
}

// ConvertToQcow2 of a layered overlay flattens the backing chain into a
// standalone image (like `qemu-img convert` with no -B).
func TestConvert_FlattensLayeredOverlay(t *testing.T) {
	for _, tc := range []struct {
		name string
		// shadowed clusters written over the base (cluster idx -> data seed; 0 = zero)
		shadows []struct {
			cluster int
			seed    byte
		}
	}{
		{"shadow_and_zero", []struct {
			cluster int
			seed    byte
		}{{3, 0xAB}, {7, 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			for _, sh := range tc.shadows {
				var data []byte
				if sh.seed == 0 {
					data = make([]byte, clusterSize)
				} else {
					data = patterned(sh.seed, clusterSize)
				}
				if _, err := w.WriteAt(data, int64(sh.cluster)*int64(clusterSize)); err != nil {
					t.Fatalf("WriteAt cluster %d: %v", sh.cluster, err)
				}
			}
			w.Sync()
			w.Close()

			// Expected flattened view: base with shadowed clusters overwritten,
			// zero-shadowed clusters zeroed.
			want := make([]byte, virtual)
			copy(want, baseView)
			for _, sh := range tc.shadows {
				var data []byte
				if sh.seed == 0 {
					data = make([]byte, clusterSize)
				} else {
					data = patterned(sh.seed, clusterSize)
				}
				copy(want[sh.cluster*clusterSize:], data)
			}

			flat := filepath.Join(dir, "flat.qcow2")
			if err := ConvertToQcow2(context.Background(), overlay, flat, ConvertDefaultOpt); err != nil {
				t.Fatalf("ConvertToQcow2 of overlay: %v", err)
			}
			assertGuestView(t, flat, want)
		})
	}
}

// ConvertToRaw of a raw source is effectively a sparse copy.
func TestConvert_RawToRaw(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed byte
		n    int // bytes of patterned data
	}{
		{"3_clusters", 0x33, 3 * clusterSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "src.img")
			mustWriteRaw(t, src, 0, patterned(tc.seed, tc.n))
			dst := filepath.Join(dir, "dst.img")
			if err := ConvertToRaw(context.Background(), src, dst); err != nil {
				t.Fatalf("ConvertToRaw: %v", err)
			}
			assertGuestView(t, dst, patterned(tc.seed, tc.n))
		})
	}
}

func assertGuestView(t *testing.T, path string, want []byte) {
	t.Helper()
	img := openGuestImageFile(t, path)
	defer img.Close()
	got := make([]byte, len(want))
	n, err := img.ReadAt(got, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt %s: %v", path, err)
	}
	// Verify the full guest view was returned before comparing contents: a
	// truncated read whose prefix matches `want` would otherwise pass silently.
	if n != len(want) {
		t.Fatalf("%s view length: got %d want %d", path, n, len(want))
	}
	if !bytes.Equal(got[:n], want[:n]) {
		for i := 0; i < n; i++ {
			if got[i] != want[i] {
				t.Fatalf("%s view differs at byte %d (cluster %d): got %#x want %#x",
					path, i, i/clusterSize, got[i], want[i])
			}
		}
		// Unreachable when the prefix-equal check above is sound, but guard
		// against a bytes.Equal mismatch the loop failed to localize.
		t.Fatalf("%s view differs from expected (see bytes above)", path)
	}
}

func TestSniffFormat(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "r.img")
	mustWriteRaw(t, raw, 0, patterned(0x01, 1024))
	q := filepath.Join(dir, "o.qcow2")
	if err := CreateOverlay(context.Background(), raw, q); err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"raw", raw, "raw"},
		{"qcow2", q, "qcow2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SniffFormat(tc.path); got != tc.want {
				t.Errorf("SniffFormat(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}
