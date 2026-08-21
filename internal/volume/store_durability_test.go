package volume

import (
	"fmt"
	"testing"

	"uml-container/internal/fsjson"
)

// injectDurability swaps the persistence seam: commit=true persists the new
// record and then reports fsjson.ErrDurability (rename committed, durability
// confirmation failed); commit=false reports it without persisting. The
// original seam is restored automatically via t.Cleanup, so a t.Fatalf
// between swap and manual restore cannot leak the stub into later tests.
func injectDurability(t *testing.T, commit bool) {
	t.Helper()
	orig := writeJSON
	if commit {
		writeJSON = func(path string, v any) error {
			if err := fsjson.Write(path, v); err != nil {
				return err
			}
			return fmt.Errorf("%w: sync (injected)", fsjson.ErrDurability)
		}
	} else {
		writeJSON = func(path string, v any) error {
			return fmt.Errorf("%w: sync (injected, not committed)", fsjson.ErrDurability)
		}
	}
	t.Cleanup(func() { writeJSON = orig })
}

// TestStore_RefCountDurabilityReconciled covers the fsjson.ErrDurability
// paths in IncRef/DecRef: when the rename committed but the directory-sync
// confirmation failed, the store must re-read the record and treat the
// change as applied only if the on-disk RefCount matches the intended
// value — surfacing the error instead would make callers retry an applied
// increment/decrement and double-count.
func TestStore_RefCountDurabilityReconciled(t *testing.T) {
	s := NewStore(t.TempDir())
	if err := s.Create(VolumeRecord{VolumeID: "vol-dur", Name: "durability", RefCount: 1}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// IncRef: rename committed, durability unconfirmed -> success, exactly
	// one applied increment.
	injectDurability(t, true)
	if err := s.IncRef("vol-dur"); err != nil {
		t.Fatalf("IncRef must reconcile ErrDurability: %v", err)
	}
	rec, err := s.Get("vol-dur")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec.RefCount != 2 {
		t.Fatalf("RefCount = %d, want 2", rec.RefCount)
	}

	// DecRef: rename committed, durability unconfirmed -> success.
	injectDurability(t, true)
	if err := s.DecRef("vol-dur"); err != nil {
		t.Fatalf("DecRef must reconcile ErrDurability: %v", err)
	}
	rec, _ = s.Get("vol-dur")
	if rec.RefCount != 1 {
		t.Fatalf("RefCount = %d, want 1", rec.RefCount)
	}

	// Durability error without the change on disk: the error must surface
	// and RefCount must be untouched.
	injectDurability(t, false)
	if err := s.IncRef("vol-dur"); err == nil {
		t.Fatalf("IncRef must fail when the re-read does not match")
	}
	rec, _ = s.Get("vol-dur")
	if rec.RefCount != 1 {
		t.Fatalf("RefCount = %d, want 1 after failed IncRef", rec.RefCount)
	}
}
