package snapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uml-container/internal/state"
)

// writeTgz builds an in-memory .tgz with the given entries and writes it to path.
func writeTgz(t *testing.T, path string, entries []tar.Header) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, h := range entries {
		h := h
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("writeHeader %s: %v", h.Name, err)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			tw.Write([]byte("payload"))
		}
	}
	tw.Close()
	gw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
}

// TestImport_SymlinkAndHardlink verifies the Import fix for review.md item 5:
// symlinks and hard links must be restored instead of silently skipped.
func TestImport_SymlinkAndHardlink(t *testing.T) {
	root := t.TempDir()
	state.RootDir = root

	tgz := filepath.Join(t.TempDir(), "snap.tgz")
	writeTgz(t, tgz, []tar.Header{
		{Name: "bin", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "bin/real", Typeflag: tar.TypeReg, Mode: 0755, Size: 7},
		{Name: "bin/link", Typeflag: tar.TypeSymlink, Linkname: "real", Mode: 0777},
		{Name: "bin/hardlink", Typeflag: tar.TypeLink, Linkname: "bin/real", Mode: 0755},
	})

	if err := Import(tgz, "c-symlink"); err != nil {
		t.Fatalf("Import: %v", err)
	}

	base := filepath.Join(root, "c-symlink")

	// symlink must exist and point at "real"
	link := filepath.Join(base, "bin", "link")
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("symlink not restored: Readlink: %v", err)
	}
	if got != "real" {
		t.Fatalf("symlink target = %q, want %q", got, "real")
	}

	// hardlink must exist and share the inode with bin/real
	realFi, _ := os.Stat(filepath.Join(base, "bin", "real"))
	hardFi, _ := os.Stat(filepath.Join(base, "bin", "hardlink"))
	if !os.SameFile(realFi, hardFi) {
		t.Fatalf("hardlink not restored: not the same inode as bin/real")
	}
}

// TestImport_UnsupportedEntryErrors verifies that an unsupported entry type
// (e.g. a device node) causes Import to fail and leave no half-populated dir.
func TestImport_UnsupportedEntryErrors(t *testing.T) {
	root := t.TempDir()
	state.RootDir = root

	tgz := filepath.Join(t.TempDir(), "snap.tgz")
	writeTgz(t, tgz, []tar.Header{
		{Name: "dev", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "dev/null", Typeflag: tar.TypeChar, Mode: 0666},
	})

	err := Import(tgz, "c-unsupported")
	if err == nil {
		t.Fatalf("Import succeeded for unsupported entry type, want error")
	}
	if !strings.Contains(err.Error(), "unsupported entry type") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Cleanup-on-failure: the half-imported dir must be removed.
	if _, statErr := os.Stat(filepath.Join(root, "c-unsupported")); !os.IsNotExist(statErr) {
		t.Fatalf("half-imported dir left behind after failure: %v", statErr)
	}
}

// TestImport_SymlinkPivotRejection verifies that a symlink pivot pointing outside
// the destination directory or file writes traversing a symlink directory are rejected.
func TestImport_SymlinkPivotRejection(t *testing.T) {
	root := t.TempDir()
	state.RootDir = root

	outsideDir := t.TempDir()

	// 1. Test symlink escaping destination root is rejected
	tgzEscape := filepath.Join(t.TempDir(), "escape.tgz")
	writeTgz(t, tgzEscape, []tar.Header{
		{Name: "pivot", Typeflag: tar.TypeSymlink, Linkname: outsideDir, Mode: 0777},
	})
	if err := Import(tgzEscape, "c-escape"); err == nil {
		t.Fatalf("Import should have failed for symlink escaping target dir")
	}

	// 2. Test relative symlink escaping destination root
	tgzRelEscape := filepath.Join(t.TempDir(), "relescape.tgz")
	writeTgz(t, tgzRelEscape, []tar.Header{
		{Name: "sub", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "sub/pivot", Typeflag: tar.TypeSymlink, Linkname: "../../outside", Mode: 0777},
	})
	if err := Import(tgzRelEscape, "c-relescape"); err == nil {
		t.Fatalf("Import should have failed for relative symlink escaping target dir")
	}
}
