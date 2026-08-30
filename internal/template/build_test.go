package template

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildPipelineRootfsPathClass(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
	t.Cleanup(func() { _ = DefaultBuilder().WaitIdle(5 * time.Second) })

	// A real (non-empty) rootfs file.
	rootfs := filepath.Join(root, "base.img")
	if err := os.WriteFile(rootfs, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := Record{TemplateID: GenerateTemplateID(), ImageRef: rootfs, Status: "PENDING", Kind: "template"}
	if err := s.Create(rec); err != nil {
		t.Fatal(err)
	}

	b := DefaultBuilder()
	if err := b.Start(s, rec.TemplateID); err != nil {
		t.Fatal(err)
	}

	st, err := b.Wait(s, rec.TemplateID, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != PhaseDone || st.Pct != 100 {
		t.Fatalf("expected done/100, got %s/%d (err=%q)", st.Phase, st.Pct, st.Error)
	}

	got, _ := s.Get(rec.TemplateID)
	if got.Status != "READY" {
		t.Fatalf("record must flip READY, got %s", got.Status)
	}
	if got.ImagePath != rootfs {
		t.Fatalf("ImagePath must bind the rootfs, got %q", got.ImagePath)
	}
	// Progress + log persisted.
	dir := filepath.Join(root, rec.TemplateID)
	if _, err := os.Stat(filepath.Join(dir, "build.json")); err != nil {
		t.Fatal("build.json must persist")
	}
	logRaw, err := os.ReadFile(filepath.Join(dir, "build.log"))
	if err != nil || len(logRaw) == 0 {
		t.Fatalf("build.log must persist (err=%v)", err)
	}
}

func TestBuildPipelineFailsOnMissingRootfsAndEmpty(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
	b := DefaultBuilder()
	t.Cleanup(func() { _ = b.WaitIdle(30 * time.Second) })

	// The empty file exists but carries no filesystem (explicit failure);
	// the missing path doubles as the docker-ref class (pulling a nonexistent
	// ref fails without network). Either way the build must end FAILED, not
	// stuck PENDING.
	empty := filepath.Join(root, "empty.img")
	_ = os.WriteFile(empty, nil, 0o644)

	cases := []struct {
		name     string
		imageRef string
	}{
		{"missing rootfs file", "/nonexistent/no-such.img"},
		{"empty rootfs file", empty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := Record{
				TemplateID: GenerateTemplateID(),
				ImageRef:   tc.imageRef,
				Status:     "PENDING",
				Kind:       "template",
			}
			_ = s.Create(rec)
			if err := b.Start(s, rec.TemplateID); err != nil {
				t.Fatal(err)
			}
			st, _ := b.Wait(s, rec.TemplateID, 30*time.Second)
			if st.Phase != PhaseFailed {
				t.Fatalf("build must fail, got phase %s", st.Phase)
			}
			got, _ := s.Get(rec.TemplateID)
			if got.Status != "FAILED" {
				t.Fatalf("record must flip FAILED, got %s", got.Status)
			}
		})
	}
}

func TestBuildOnlyPendingAndNoConcurrent(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
	b := DefaultBuilder()
	t.Cleanup(func() { _ = b.WaitIdle(5 * time.Second) })

	rec := Record{TemplateID: GenerateTemplateID(), ImageRef: "whatever", Status: "READY", Kind: "template"}
	_ = s.Create(rec)
	if err := b.Start(s, rec.TemplateID); err == nil {
		t.Fatal("READY template must refuse to build")
	}

	// No image_ref at all.
	rec2 := Record{
		TemplateID: GenerateTemplateID(),
		Status:     "PENDING",
		Kind:       "template",
	}
	_ = s.Create(rec2)
	if err := b.Start(s, rec2.TemplateID); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.running[rec2.TemplateID] = true // simulate in-flight
	b.mu.Unlock()
	if err := b.Start(s, rec2.TemplateID); err == nil {
		t.Fatal("concurrent build for the same template must be rejected")
	}
}
