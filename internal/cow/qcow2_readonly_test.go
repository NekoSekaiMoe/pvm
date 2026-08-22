// qcow2_readonly_test.go — OpenReadOnly: reads work (raw and qcow2 with a
// backing chain), writes fail closed, and the underlying file is never
// mutated (the fd is O_RDONLY even if a write slipped past the wrapper).
package cow

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenReadOnly_RawRejectsWrites(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	mustWriteRaw(t, base, 0, patterned(0x11, 4*clusterSize))

	be, err := OpenReadOnly(base)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer be.Close()

	// Reads return the backing bytes.
	buf := make([]byte, clusterSize)
	if _, err := be.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	want := patterned(0x11, clusterSize)
	for i := range buf {
		if buf[i] != want[i] {
			t.Fatalf("read mismatch at %d: %#x != %#x", i, buf[i], want[i])
		}
	}
	// Writes fail closed.
	if _, err := be.WriteAt(patterned(0xE5, 512), 0); err == nil {
		t.Fatal("WriteAt accepted on read-only backend")
	}
	// Size matches the image.
	if be.Size() != int64(4*clusterSize) {
		t.Fatalf("Size = %d, want %d", be.Size(), 4*clusterSize)
	}
}

func TestOpenReadOnly_Qcow2BackingChainReads(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	baseData := patterned(0x22, 4*clusterSize)
	mustWriteRaw(t, base, 0, baseData)
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create: %v", err)
	}

	be, err := OpenReadOnly(overlay)
	if err != nil {
		t.Fatalf("OpenReadOnly(qcow2): %v", err)
	}
	defer be.Close()

	// Reads fall through the unallocated overlay to the backing.
	buf := make([]byte, 2*clusterSize)
	if _, err := be.ReadAt(buf, clusterSize); err != nil {
		t.Fatalf("ReadAt through backing: %v", err)
	}
	want := baseData[clusterSize : 3*clusterSize]
	for i := range buf {
		if buf[i] != want[i] {
			t.Fatalf("backing read mismatch at %d: %#x != %#x", i, buf[i], want[i])
		}
	}
	// Writes still fail.
	if _, err := be.WriteAt(patterned(0xE5, 512), 0); err == nil {
		t.Fatal("WriteAt accepted on read-only qcow2 backend")
	}
}

func TestOpenReadOnly_FileUntouched(t *testing.T) {
	// Belt-and-suspenders: even a bug that bypassed the wrapper's WriteAt
	// error could not mutate the image — the fd is read-only. Verify the
	// wrapper holds no write path by checking the file content after use.
	dir := t.TempDir()
	base := filepath.Join(dir, "base.img")
	orig := patterned(0x33, clusterSize)
	mustWriteRaw(t, base, 0, orig)

	be, err := OpenReadOnly(base)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	if _, err := be.WriteAt(patterned(0xFF, 512), 0); err == nil {
		t.Fatal("WriteAt accepted")
	}
	be.Close()

	got, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	for i := range orig {
		if got[i] != orig[i] {
			t.Fatalf("base image mutated at %d despite read-only open", i)
		}
	}
}
