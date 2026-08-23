package uidalloc

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *Table {
	t.Helper()
	tbl, err := Open(filepath.Join(t.TempDir(), "uidmap.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return tbl
}

func TestAllocateAssignsSequentialRanges(t *testing.T) {
	tbl := openTemp(t)
	ids := []string{"c1", "c2", "c3"}
	want := []uint32{FirstBase, FirstBase + RangeSize, FirstBase + 2*RangeSize}
	for i, id := range ids {
		base, err := tbl.Allocate(id)
		if err != nil {
			t.Fatalf("Allocate(%q): %v", id, err)
		}
		if base != want[i] {
			t.Errorf("Allocate(%q) = %d, want %d", id, base, want[i])
		}
	}
}

func TestAllocateIsIdempotent(t *testing.T) {
	tbl := openTemp(t)
	b1, err := tbl.Allocate("c1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tbl.Allocate("c2"); err != nil {
		t.Fatal(err)
	}
	b2, err := tbl.Allocate("c1")
	if err != nil {
		t.Fatal(err)
	}
	if b1 != b2 {
		t.Errorf("re-Allocate(c1) = %d, want original %d", b2, b1)
	}
}

func TestReleaseFreesSlotForReuse(t *testing.T) {
	tbl := openTemp(t)
	b1, _ := tbl.Allocate("c1")
	if _, err := tbl.Allocate("c2"); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Release("c1"); err != nil {
		t.Fatal(err)
	}
	b3, err := tbl.Allocate("c3")
	if err != nil {
		t.Fatal(err)
	}
	if b3 != b1 {
		t.Errorf("Allocate(c3) after Release(c1) = %d, want freed slot %d", b3, b1)
	}
	// Releasing an unknown id must be a no-op (cleanup paths rely on it).
	if err := tbl.Release("never-allocated"); err != nil {
		t.Errorf("Release(unknown): %v", err)
	}
}

func TestLookupDoesNotAssign(t *testing.T) {
	tbl := openTemp(t)
	if _, ok, err := tbl.Lookup("ghost"); err != nil || ok {
		t.Errorf("Lookup(ghost) = ok=%v err=%v, want ok=false err=nil", ok, err)
	}
	b, _ := tbl.Allocate("c1")
	got, ok, err := tbl.Lookup("c1")
	if err != nil || !ok || got != b {
		t.Errorf("Lookup(c1) = %d,%v,%v want %d,true,nil", got, ok, err, b)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uidmap.json")
	t1, _ := Open(path)
	b1, err := t1.Allocate("c1")
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := Open(path)
	got, ok, err := t2.Lookup("c1")
	if err != nil || !ok || got != b1 {
		t.Fatalf("reopened Lookup(c1) = %d,%v,%v want %d,true,nil", got, ok, err, b1)
	}
	// A second table on the same file must not double-book the slot.
	b2, err := t2.Allocate("c2")
	if err != nil {
		t.Fatal(err)
	}
	if b2 == b1 {
		t.Errorf("second table Allocate(c2) collided with c1 at %d", b2)
	}
}

func TestPrune(t *testing.T) {
	tbl := openTemp(t)
	for _, id := range []string{"c1", "c2", "c3"} {
		if _, err := tbl.Allocate(id); err != nil {
			t.Fatal(err)
		}
	}
	n, err := tbl.Prune(map[string]bool{"c2": true})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("Prune removed %d, want 2", n)
	}
	if _, ok, _ := tbl.Lookup("c1"); ok {
		t.Error("c1 should have been pruned")
	}
	if _, ok, _ := tbl.Lookup("c2"); !ok {
		t.Error("c2 should have been kept")
	}
}

func TestInvalidIDs(t *testing.T) {
	tbl := openTemp(t)
	for _, id := range []string{"", "a/b", "a b", "../x", "ümlaut"} {
		if _, err := tbl.Allocate(id); err == nil {
			t.Errorf("Allocate(%q) succeeded, want error", id)
		}
		if _, _, err := tbl.Lookup(id); err == nil {
			t.Errorf("Lookup(%q) succeeded, want error", id)
		}
	}
}

func TestLowestFreeOverflow(t *testing.T) {
	// Fill the grid synthetically near the top of the uid space to exercise
	// the exhaustion path without 65k loop iterations.
	alloc := map[string]uint32{}
	for b := uint64(FirstBase); b <= maxBase; b += RangeSize {
		alloc[fmt.Sprintf("c%d", b)] = uint32(b)
	}
	if _, err := lowestFree(alloc); err == nil {
		t.Error("lowestFree on full grid succeeded, want exhaustion error")
	}
}

func TestCorruptTableReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uidmap.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	tbl, _ := Open(path)
	if _, err := tbl.Allocate("c1"); err == nil {
		t.Error("Allocate on corrupt table succeeded, want corruption error")
	}
}

func TestRangesDoNotOverlap(t *testing.T) {
	tbl := openTemp(t)
	const n = 8
	seen := map[uint32]string{}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("c%d", i)
		base, err := tbl.Allocate(id)
		if err != nil {
			t.Fatal(err)
		}
		for uid := base; uid < base+RangeSize; uid++ {
			if owner, dup := seen[uid]; dup {
				t.Fatalf("uid %d mapped to both %s and %s", uid, owner, id)
			}
			seen[uid] = id
		}
	}
}
