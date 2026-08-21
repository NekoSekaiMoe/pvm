package template

import (
	"fmt"
	"testing"

	"uml-container/internal/fsjson"
)

// TestStore drives the Store scenarios as a table of named cases executed
// via t.Run: create + alias resolution, list + delete, and SetAlias
// claim/clear.
func TestStore(t *testing.T) {
	cases := []struct {
		name string
		fn   func(t *testing.T, s *Store)
	}{
		{"create and resolve alias", func(t *testing.T, s *Store) {
			rec := Record{TemplateID: GenerateTemplateID(), Alias: "my-alias", ImageRef: "ubuntu:22.04"}
			if err := s.Create(rec); err != nil {
				t.Fatalf("create: %v", err)
			}

			// resolve alias -> id
			got, err := s.ResolveIdentifier("my-alias")
			if err != nil {
				t.Fatalf("resolve alias: %v", err)
			}
			if got != rec.TemplateID {
				t.Fatalf("alias resolved to %q, want %q", got, rec.TemplateID)
			}

			// resolve raw id passthrough
			got2, err := s.ResolveIdentifier(rec.TemplateID)
			if err != nil || got2 != rec.TemplateID {
				t.Fatalf("raw id resolve: got %q err %v", got2, err)
			}

			// duplicate alias
			rec2 := Record{TemplateID: GenerateTemplateID(), Alias: "my-alias"}
			if err := s.Create(rec2); err == nil {
				t.Fatalf("expected duplicate alias error")
			}
		}},
		{"list and delete", func(t *testing.T, s *Store) {
			for i := 0; i < 3; i++ {
				if err := s.Create(Record{TemplateID: GenerateTemplateID()}); err != nil {
					t.Fatalf("create %d: %v", i, err)
				}
			}
			list, err := s.List()
			if err != nil || len(list) != 3 {
				t.Fatalf("list: %v len=%d", err, len(list))
			}
			if err := s.Delete(list[0].TemplateID); err != nil {
				t.Fatalf("delete: %v", err)
			}
			list2, _ := s.List()
			if len(list2) != 2 {
				t.Fatalf("after delete len=%d, want 2", len(list2))
			}
		}},
		{"set alias", func(t *testing.T, s *Store) {
			id := GenerateTemplateID()
			if err := s.Create(Record{TemplateID: id}); err != nil {
				t.Fatalf("create: %v", err)
			}
			if err := s.SetAlias(id, "new-alias"); err != nil {
				t.Fatalf("set alias: %v", err)
			}
			rec, _ := s.Get(id)
			if rec.Alias != "new-alias" {
				t.Fatalf("alias not set: %q", rec.Alias)
			}
			if err := s.SetAlias(id, ""); err != nil {
				t.Fatalf("clear alias: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, NewStore(t.TempDir()))
		})
	}
}

// TestStore_CreateRejectsAliasOnNonReady verifies aliases can only be
// claimed by READY templates (the status default is applied before the gate,
// so an explicit PENDING with an alias is rejected).
func TestStore_CreateRejectsAliasOnNonReady(t *testing.T) {
	s := NewStore(t.TempDir())
	err := s.Create(Record{TemplateID: GenerateTemplateID(), Alias: "ghost", Status: "PENDING"})
	if err == nil {
		t.Fatalf("expected error for alias on PENDING template")
	}
	if _, gerr := s.GetByAlias("ghost"); gerr == nil {
		t.Fatalf("alias must not be indexed for non-READY template")
	}
}

// TestStore_AliasIndex_InitFromDisk verifies that the alias index is
// populated from records already on disk, so a fresh Store resolves aliases
// and enforces uniqueness without a directory scan.
func TestStore_AliasIndex_InitFromDisk(t *testing.T) {
	root := t.TempDir()
	s1 := NewStore(root)
	id := GenerateTemplateID()
	if err := s1.Create(Record{TemplateID: id, Alias: "warm"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	s2 := NewStore(root)
	got, err := s2.GetByAlias("warm")
	if err != nil {
		t.Fatalf("fresh store must resolve disk alias: %v", err)
	}
	if got.TemplateID != id {
		t.Fatalf("alias resolved to %q, want %q", got.TemplateID, id)
	}
	if err := s2.Create(Record{TemplateID: GenerateTemplateID(), Alias: "warm"}); err == nil {
		t.Fatalf("fresh store must enforce alias uniqueness")
	}
}

// TestStore_AliasIndex_MoveAndRelease verifies the index is maintained on
// SetAlias (old alias freed, moved-off alias claimable) and Delete (alias
// released).
func TestStore_AliasIndex_MoveAndRelease(t *testing.T) {
	s := NewStore(t.TempDir())
	id := GenerateTemplateID()
	if err := s.Create(Record{TemplateID: id, Alias: "x"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// move alias x -> y
	if err := s.SetAlias(id, "y"); err != nil {
		t.Fatalf("set alias: %v", err)
	}
	if _, err := s.GetByAlias("x"); err == nil {
		t.Fatalf("old alias still resolvable after move")
	}
	if got, err := s.GetByAlias("y"); err != nil || got.TemplateID != id {
		t.Fatalf("new alias not resolvable: got %+v err %v", got, err)
	}

	// alias moved off ("x") is claimable by another template
	id2 := GenerateTemplateID()
	if err := s.Create(Record{TemplateID: id2, Alias: "x"}); err != nil {
		t.Fatalf("moved-off alias not claimable: %v", err)
	}

	// delete drops the index entry; the alias becomes reusable
	if err := s.Delete(id2); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetByAlias("x"); err == nil {
		t.Fatalf("alias still resolvable after template delete")
	}
	if err := s.Create(Record{TemplateID: GenerateTemplateID(), Alias: "x"}); err != nil {
		t.Fatalf("alias not released after delete: %v", err)
	}

	// empty-alias error preserved
	if _, err := s.GetByAlias(""); err == nil {
		t.Fatalf("empty alias must error")
	}
}

// TestStore_CreateRejectsInvalidStatusKind verifies explicit Status/Kind
// values are validated before persistence; each invalid variant is its own
// case asserting the error AND that nothing was persisted.
func TestStore_CreateRejectsInvalidStatusKind(t *testing.T) {
	cases := []struct {
		name string
		rec  Record
	}{
		{"invalid status", Record{TemplateID: GenerateTemplateID(), Status: "BOGUS"}},
		{"invalid kind", Record{TemplateID: GenerateTemplateID(), Kind: "mystery"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewStore(t.TempDir())
			if err := s.Create(c.rec); err == nil {
				t.Fatalf("invalid %s accepted", c.name)
			}
			if list, _ := s.List(); len(list) != 0 {
				t.Fatalf("invalid record was persisted: %+v", list)
			}
		})
	}
}

// injectDurability swaps the persistence seam: commit=true persists the new
// record and then reports fsjson.ErrDurability (rename committed, durability
// confirmation failed); commit=false reports it without persisting.
func injectDurability(commit bool) func() {
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
	return func() { writeJSON = orig }
}

// TestStore_SetAliasDurabilityReconciled covers the fsjson.ErrDurability
// path in SetAlias: when the rename committed but the directory-sync
// confirmation failed, SetAlias must re-read the record, treat the change
// as applied when the new alias landed, and update the in-memory alias
// index — surfacing the error instead would make callers retry an
// already-applied change.
func TestStore_SetAliasDurabilityReconciled(t *testing.T) {
	s := NewStore(t.TempDir())
	id := GenerateTemplateID()
	if err := s.Create(Record{TemplateID: id, Alias: "old-alias", ImageRef: "ubuntu:22.04", Status: "READY"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Rename committed, durability unconfirmed: reconcile to success.
	restore := injectDurability(true)
	if err := s.SetAlias(id, "new-alias"); err != nil {
		t.Fatalf("SetAlias must reconcile ErrDurability: %v", err)
	}
	restore()

	dir, err := s.dir(id)
	if err != nil {
		t.Fatalf("dir: %v", err)
	}
	got, err := readMeta(dir)
	if err != nil || got.Alias != "new-alias" {
		t.Fatalf("on-disk alias = (%v, %v), want new-alias", got, err)
	}
	if resolved, err := s.ResolveIdentifier("new-alias"); err != nil || resolved != id {
		t.Fatalf("alias index not updated: (%q, %v)", resolved, err)
	}
	if _, err := s.GetByAlias("old-alias"); err == nil {
		t.Fatalf("old alias still resolvable after move")
	}

	// Durability error without the change on disk: the error must surface
	// so the caller knows nothing was applied.
	restore = injectDurability(false)
	if err := s.SetAlias(id, "other-alias"); err == nil {
		t.Fatalf("SetAlias must fail when the re-read does not match")
	}
	restore()
	if _, err := s.GetByAlias("other-alias"); err == nil {
		t.Fatalf("alias index updated despite failed commit")
	}
}
