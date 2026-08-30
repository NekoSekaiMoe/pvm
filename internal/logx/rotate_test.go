package logx

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotationShiftsGenerations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "console.log")
	r, err := NewRotator(path, 64, 3)
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.Repeat("x", 30)
	for i := 0; i < 8; i++ {
		if _, err := r.Write([]byte(blob + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	_ = r.Close()

	// Current + up to 3 generations exist; oldest generation is gone.
	for _, name := range []string{"console.log", "console.log.1", "console.log.2", "console.log.3"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "console.log.4")); !os.IsNotExist(err) {
		t.Fatal("generation .4 must not exist with keep=3")
	}

	// Newest generation content is the latest writes; each write stayed whole.
	raw, _ := os.ReadFile(path)
	if !bytes.HasSuffix(raw, []byte("x\n")) {
		t.Fatalf("current generation corrupted: %q", raw)
	}
	if len(raw) > 64 {
		t.Fatalf("current generation must respect the cap (got %d bytes)", len(raw))
	}
}

func TestWriteAfterCloseErrors(t *testing.T) {
	r, _ := NewRotator(filepath.Join(t.TempDir(), "a.log"), 0, 0)
	_ = r.Close()
	if _, err := r.Write([]byte("x")); err != os.ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}
