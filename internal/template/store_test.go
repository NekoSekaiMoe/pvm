package template

import (
	"testing"
)

func TestStore_CreateAndResolveAlias(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)

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
}

func TestStore_ListAndDelete(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
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
}

func TestStore_SetAlias(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
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
}
