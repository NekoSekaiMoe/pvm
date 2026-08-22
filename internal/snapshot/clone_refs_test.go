package snapshot

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"uml-container/internal/state"
)

// TestPrepareDelete_GuardsParentOfClones covers the clone→parent reference
// lifecycle: cloning records the parent link, deleting the parent is vetoed
// while the clone lives, and deleting the clone releases the claim.
func TestPrepareDelete_GuardsParentOfClones(t *testing.T) {
	oldRoot := state.RootDir
	state.RootDir = t.TempDir()
	t.Cleanup(func() { state.RootDir = oldRoot })

	srcDir := filepath.Join(state.RootDir, "src-a")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Dummy overlay bytes: whether CreateOverlay accepts it as a raw backing
	// or Clone falls back to copyFile, the parent reference must be recorded.
	if err := os.WriteFile(filepath.Join(srcDir, "overlay.qcow2"), []byte("not-a-real-qcow2"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Clone("src-a", "dst-a"); err != nil {
		t.Fatalf("Clone(src-a, dst-a): %v", err)
	}

	clones, err := ClonesOf("src-a")
	if err != nil {
		t.Fatalf("ClonesOf(src-a): %v", err)
	}
	if len(clones) != 1 || clones[0] != "dst-a" {
		t.Fatalf("ClonesOf(src-a) = %v, want [dst-a]", clones)
	}

	// Parent deletion must be vetoed while the clone's backing reaches in.
	err = PrepareDelete("src-a")
	if !errors.Is(err, ErrHasClones) {
		t.Fatalf("PrepareDelete(src-a) = %v, want ErrHasClones", err)
	}

	// Clone-of-clone: the middle container is both parent and clone.
	if err := Clone("dst-a", "dst-b"); err != nil {
		t.Fatalf("Clone(dst-a, dst-b): %v", err)
	}
	if err := PrepareDelete("dst-a"); !errors.Is(err, ErrHasClones) {
		t.Fatalf("PrepareDelete(dst-a) = %v, want ErrHasClones", err)
	}

	// Deleting the leaf releases its claim on dst-a...
	if err := PrepareDelete("dst-b"); err != nil {
		t.Fatalf("PrepareDelete(dst-b): %v", err)
	}
	if clones, _ = ClonesOf("dst-a"); len(clones) != 0 {
		t.Fatalf("ClonesOf(dst-a) = %v after leaf delete, want empty", clones)
	}
	// ...which now only holds its own claim on src-a; releasing it empties
	// the parent's refs.
	if err := PrepareDelete("dst-a"); err != nil {
		t.Fatalf("PrepareDelete(dst-a) after leaf gone: %v", err)
	}
	if clones, _ = ClonesOf("src-a"); len(clones) != 0 {
		t.Fatalf("ClonesOf(src-a) = %v after clone delete, want empty", clones)
	}

	// With no live clones the parent is deletable again.
	if err := PrepareDelete("src-a"); err != nil {
		t.Fatalf("PrepareDelete(src-a) after clones gone: %v", err)
	}
}

// TestPrepareDelete_NoStorageDependency covers containers cloned WITHOUT any
// disk dependency (no overlay.qcow2 / rootfs.img in the source): those must
// not leave a marker — nothing branches from them, so deletion stays free.
func TestPrepareDelete_NoStorageDependency(t *testing.T) {
	oldRoot := state.RootDir
	state.RootDir = t.TempDir()
	t.Cleanup(func() { state.RootDir = oldRoot })

	srcDir := filepath.Join(state.RootDir, "src-b")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "state.json"), []byte(`{"id":"src-b","name":"src-b","status":"ready"}`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Clone("src-b", "dst-c"); err != nil {
		t.Fatalf("Clone(src-b, dst-c): %v", err)
	}
	if clones, err := ClonesOf("src-b"); err != nil || len(clones) != 0 {
		t.Fatalf("ClonesOf(src-b) = %v, %v; want no markers", clones, err)
	}
	if err := PrepareDelete("src-b"); err != nil {
		t.Fatalf("PrepareDelete(src-b) should be unguarded, got %v", err)
	}
}
