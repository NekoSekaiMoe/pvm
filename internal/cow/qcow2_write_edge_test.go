package cow

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// forgeForeignOverlay builds a minimal qcow2 overlay whose refcount table is
// empty (no refblocks registered) — simulating a foreign image not created by
// this package. Writes then take the lazy path: bumpRefcount must allocate
// refcount blocks, including the self-reference chain (a new block's own
// cluster falling into a not-yet-registered block) that used to recurse.
func forgeForeignOverlay(t *testing.T, path string, virtualSize uint64) {
	t.Helper()
	const cs = uint64(clusterSize)
	l2Entries := cs / 8
	l1Size := (virtualSize + l2Entries*cs - 1) / (l2Entries * cs)
	l1Clusters := (l1Size*8 + cs - 1) / cs
	// Layout: header | reftable (1) | L1. No refblocks; reftableCls 8
	// leaves room for lazy registration.
	l1Off := 2 * cs
	buf := make([]byte, l1Off+l1Clusters*cs)
	copy(buf[0:4], qcow2Magic)
	binary.BigEndian.PutUint32(buf[4:], qcow2Version3)
	binary.BigEndian.PutUint32(buf[0x14:], clusterBits)
	binary.BigEndian.PutUint64(buf[0x18:], virtualSize)
	binary.BigEndian.PutUint32(buf[0x24:], uint32(l1Size))
	binary.BigEndian.PutUint64(buf[0x28:], l1Off)
	binary.BigEndian.PutUint64(buf[0x30:], cs) // reftable at cluster 1
	binary.BigEndian.PutUint32(buf[0x38:], 8)  // 8 reftable clusters
	binary.BigEndian.PutUint32(buf[0x60:], refcountOrder)
	binary.BigEndian.PutUint32(buf[0x64:], qcow2HeaderLen)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatalf("forge overlay: %v", err)
	}
}

// TestQcow2Write_ForeignLazyRefblocks: every allocation on an image without
// pre-registered refcount blocks must end with refcount 1 for the data
// cluster AND 1 for every refcount block allocated along the way, including
// the self-reference chain — read back through the tables to prove it.
func TestQcow2Write_ForeignLazyRefblocks(t *testing.T) {
	dir := t.TempDir()
	const vs = uint64(64) << 20
	ov := filepath.Join(dir, "foreign.qcow2")
	forgeForeignOverlay(t, ov, vs)

	be, err := OpenWritable(ov)
	if err != nil {
		t.Fatalf("open writable: %v", err)
	}
	defer be.Close()
	// Write at offsets whose host clusters land in the first refblock (0),
	// forcing: data cluster -> missing refblock #0 -> allocate -> self
	// cluster of that block -> possibly missing block again (chain).
	for i := 0; i < 8; i++ {
		off := int64(i * clusterSize * 1024)
		if _, err := be.WriteAt(patterned(byte(0x40+i), clusterSize), off); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := be.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Verify refcounts through the table: reftable[0] must point at a
	// refblock; every metadata cluster below EOF (header, reftable, L1,
	// refblocks themselves) must have refcount 1, not 0.
	f, err := os.Open(ov)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var hdr [qcow2HeaderLen]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	if st.Size()%clusterSize != 0 {
		t.Fatalf("file size %#x not cluster-aligned", st.Size())
	}
	refblockOff := func(blockIdx uint64) uint64 {
		var e [8]byte
		if _, err := f.ReadAt(e[:], int64(clusterSize+blockIdx*8)); err != nil {
			t.Fatal(err)
		}
		off := binary.BigEndian.Uint64(e[:]) & reftOffsetMask
		if off == 0 {
			t.Fatalf("reftable[%d] unregistered", blockIdx)
		}
		return off
	}
	refcount := func(clusterIdx uint64) uint16 {
		off := refblockOff(clusterIdx/(clusterSize/2)) + (clusterIdx%(clusterSize/2))*2
		var c [2]byte
		if _, err := f.ReadAt(c[:], int64(off)); err != nil {
			t.Fatal(err)
		}
		return binary.BigEndian.Uint16(c[:])
	}
	// Every cluster the WRITER allocated must be accounted (refcount 1) —
	// data clusters, L2 tables, and the refblocks themselves including the
	// self-reference chain. (The forged prefix — header/reftable/L1 — never
	// had refcounts; that pre-existing state is the forge's, not ours.)
	l2Entries := uint64(clusterSize / 8)
	l1Size := (vs + l2Entries*clusterSize - 1) / (l2Entries * clusterSize)
	l1Clusters := (l1Size*8 + uint64(clusterSize) - 1) / clusterSize
	forgedEnd := 2 + l1Clusters
	nClusters := uint64(st.Size()) / clusterSize
	if nClusters <= forgedEnd {
		t.Fatalf("file did not grow: %d clusters (forged prefix %d)", nClusters, forgedEnd)
	}
	for c := forgedEnd; c < nClusters; c++ {
		if got := refcount(c); got != 1 {
			t.Errorf("refcount[cluster %d] = %d, want 1 (leaked/over-counted cluster)", c, got)
		}
	}

	// And the data reads back.
	img, err := openGuestImage(ov)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	got := make([]byte, clusterSize)
	off := 3 * clusterSize * 1024
	if _, err := img.ReadAt(got, int64(off)); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !equalBytes(got, patterned(0x43, clusterSize)) {
		t.Error("written data readback mismatch")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestQcow2Write_RefcountTableFullGuard: an allocation beyond the reftable's
// coverage must fail cleanly instead of panicking or corrupting the table.
func TestQcow2Write_RefcountTableFullGuard(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "tiny.qcow2")
	// Forge an overlay with a reftable of exactly 1 cluster and NO refblocks,
	// then shrink hdr.refcountClusters so the table covers fewer blocks than
	// the file already spans: the very first bump must hit the guard.
	forgeForeignOverlay(t, ov, 1<<20)
	f, err := os.OpenFile(ov, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var one [4]byte
	binary.BigEndian.PutUint32(one[:], 0) // refcount_clusters = 0
	if _, err := f.WriteAt(one[:], 0x38); err != nil {
		t.Fatal(err)
	}
	f.Close()

	be, err := OpenWritable(ov)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer be.Close()
	if _, err := be.WriteAt(patterned(0x66, 512), 0); err == nil {
		t.Fatal("expected refcount-table-full error, got success")
	} else if got := err.Error(); !contains(got, "refcount table full") {
		t.Fatalf("error = %q, want refcount table full", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
