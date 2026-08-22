package tarutil

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tarEntry is one archive member spec for buildTar: its tar header plus
// (for regular files) its content.
type tarEntry struct {
	hdr  tar.Header
	data []byte
}

// buildTar assembles an uncompressed tar from header/content specs.
func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&e.hdr); err != nil {
			t.Fatalf("WriteHeader %s: %v", e.hdr.Name, err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatalf("write data: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func TestExtract_HappyPath(t *testing.T) {
	dir := t.TempDir()
	data := buildTar(t, []tarEntry{
		{tar.Header{Name: "etc", Typeflag: tar.TypeDir, Mode: 0755}, nil},
		{tar.Header{Name: "etc/conf", Typeflag: tar.TypeReg, Mode: 0644, Size: 5}, []byte("hello")},
	})
	if err := Extract(bytes.NewReader(data), dir, DefaultLimits()); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "etc", "conf"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("extracted file wrong: %q err=%v", got, err)
	}
}

func TestExtract_RejectsTraversalAndAbsolute(t *testing.T) {
	for _, name := range []string{"../evil", "a/../../evil", "/etc/passwd", "./x/../../../evil"} {
		dir := t.TempDir()
		data := buildTar(t, []tarEntry{
			{tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0644, Size: 1}, []byte("x")},
		})
		err := Extract(bytes.NewReader(data), dir, DefaultLimits())
		if err == nil {
			t.Fatalf("member %q: expected rejection", name)
		}
		if _, serr := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); serr == nil {
			t.Fatalf("member %q escaped destination", name)
		}
	}
}

func TestExtract_RejectsDeviceNode(t *testing.T) {
	dir := t.TempDir()
	data := buildTar(t, []tarEntry{
		{tar.Header{Name: "dev/null", Typeflag: tar.TypeChar, Mode: 0666}, nil},
	})
	err := Extract(bytes.NewReader(data), dir, DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "unsupported entry type") {
		t.Fatalf("expected unsupported-entry error, got: %v", err)
	}
}

func TestExtract_SymlinkRules(t *testing.T) {
	outside := t.TempDir()

	t.Run("absolute_target_rejected", func(t *testing.T) {
		dir := t.TempDir()
		data := buildTar(t, []tarEntry{
			{tar.Header{Name: "pivot", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0777}, nil},
		})
		if err := Extract(bytes.NewReader(data), dir, DefaultLimits()); err == nil {
			t.Fatal("absolute symlink target must be rejected")
		}
	})

	t.Run("escaping_relative_target_rejected", func(t *testing.T) {
		dir := t.TempDir()
		data := buildTar(t, []tarEntry{
			{tar.Header{Name: "sub/pivot", Typeflag: tar.TypeSymlink, Linkname: "../../outside", Mode: 0777}, nil},
		})
		if err := Extract(bytes.NewReader(data), dir, DefaultLimits()); err == nil {
			t.Fatal("escaping relative symlink must be rejected")
		}
	})

	t.Run("internal_symlink_ok", func(t *testing.T) {
		dir := t.TempDir()
		data := buildTar(t, []tarEntry{
			{tar.Header{Name: "real", Typeflag: tar.TypeReg, Mode: 0644, Size: 2}, []byte("ok")},
			{tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "real", Mode: 0777}, nil},
		})
		if err := Extract(bytes.NewReader(data), dir, DefaultLimits()); err != nil {
			t.Fatalf("internal symlink rejected: %v", err)
		}
	})
}

func TestExtract_PivotAttackRejected(t *testing.T) {
	dir := t.TempDir()
	data := buildTar(t, []tarEntry{
		{tar.Header{Name: "sub", Typeflag: tar.TypeDir, Mode: 0755}, nil},
		// ".." itself stays inside dest (resolves to the dest root)...
		{tar.Header{Name: "sub/pivot", Typeflag: tar.TypeSymlink, Linkname: "..", Mode: 0777}, nil},
		// ...then a later member writes THROUGH the pivot below the root.
		{tar.Header{Name: "sub/pivot/evil", Typeflag: tar.TypeReg, Mode: 0644, Size: 1}, []byte("p")},
	})
	err := Extract(bytes.NewReader(data), dir, DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "traverses symlink") {
		t.Fatalf("pivot attack must be rejected with traverses-symlink error, got: %v", err)
	}
}

func TestExtract_LimitsEnforced(t *testing.T) {
	t.Run("per_file_cap", func(t *testing.T) {
		dir := t.TempDir()
		big := make([]byte, 100)
		data := buildTar(t, []tarEntry{
			{tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(big))}, big},
		})
		limits := Limits{MaxFileSize: 50, MaxTotalBytes: 1000, MaxEntries: 10}
		if err := Extract(bytes.NewReader(data), dir, limits); err == nil {
			t.Fatal("per-file limit must fire")
		}
	})

	t.Run("total_cap", func(t *testing.T) {
		dir := t.TempDir()
		chunk := make([]byte, 60)
		data := buildTar(t, []tarEntry{
			{tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(chunk))}, chunk},
			{tar.Header{Name: "b", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(chunk))}, chunk},
		})
		limits := Limits{MaxFileSize: 100, MaxTotalBytes: 100, MaxEntries: 10}
		if err := Extract(bytes.NewReader(data), dir, limits); err == nil {
			t.Fatal("total limit must fire")
		}
	})

	t.Run("entry_cap", func(t *testing.T) {
		dir := t.TempDir()
		var specs []tarEntry
		for i := 0; i < 3; i++ {
			specs = append(specs, tarEntry{hdr: tar.Header{Name: string(rune('a' + i)), Typeflag: tar.TypeReg, Mode: 0644}})
		}
		data := buildTar(t, specs)
		limits := Limits{MaxFileSize: 100, MaxTotalBytes: 100, MaxEntries: 2}
		if err := Extract(bytes.NewReader(data), dir, limits); err == nil {
			t.Fatal("entry cap must fire")
		}
	})

	t.Run("zero_limits_rejected", func(t *testing.T) {
		dir := t.TempDir()
		if err := Extract(bytes.NewReader(nil), dir, Limits{}); err == nil {
			t.Fatal("zero Limits must be rejected")
		}
	})
}

func TestExtract_StripsSetuidSetgidSticky(t *testing.T) {
	dir := t.TempDir()
	data := buildTar(t, []tarEntry{
		// POSIX special bits live in the LOW bits of tar's Mode field: 04000
		// setuid | 02000 setgid | 01000 sticky, combined with 0755. (Go's
		// os.ModeSetuid flags are high-bit markers and would never round-trip
		// through a tar header, making the strip check vacuous.)
		{tar.Header{Name: "suid", Typeflag: tar.TypeReg, Mode: 0o7755, Size: 1}, []byte("x")},
	})
	if err := Extract(bytes.NewReader(data), dir, DefaultLimits()); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "suid"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("special bits survived extraction: %v", fi.Mode())
	}
	if fi.Mode().Perm() != 0755 {
		t.Fatalf("perm = %v, want 0755", fi.Mode().Perm())
	}
}

func TestExtract_HardlinkSourceSymlinkRules(t *testing.T) {
	// link(2) dereferences every INTERMEDIATE component of its oldname but
	// never the final one. A symlinked ancestor of the hardlink source is
	// therefore a pivot out of dest and must stay rejected, while a source
	// name that is ITSELF a symlink (hardlinking over a symlink target name)
	// is a legitimate in-dest operation and must be accepted.
	cases := []struct {
		name    string
		entries []tarEntry
		wantErr string // "" means Extract must succeed
		// validate runs the scenario-specific filesystem assertions after
		// extraction (also after rejection, for wantErr cases).
		validate func(t *testing.T, dir string)
	}{
		{
			name: "intermediate_symlinked_ancestor_rejected",
			entries: []tarEntry{
				{tar.Header{Name: "real", Typeflag: tar.TypeDir, Mode: 0755}, nil},
				{tar.Header{Name: "real/data", Typeflag: tar.TypeReg, Mode: 0644, Size: 4}, []byte("data")},
				{tar.Header{Name: "pivot", Typeflag: tar.TypeSymlink, Linkname: "real", Mode: 0777}, nil},
				{tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: "pivot/data", Mode: 0644}, nil},
			},
			wantErr: "traverses symlink",
			validate: func(t *testing.T, dir string) {
				if _, serr := os.Lstat(filepath.Join(dir, "h")); serr == nil {
					t.Fatal("rejected hardlink must not exist")
				}
			},
		},
		{
			name: "final_source_component_symlink_accepted",
			entries: []tarEntry{
				{tar.Header{Name: "real", Typeflag: tar.TypeReg, Mode: 0644, Size: 4}, []byte("data")},
				{tar.Header{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "real", Mode: 0777}, nil},
				{tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: "alias", Mode: 0644}, nil},
			},
			validate: func(t *testing.T, dir string) {
				// link(2) did not dereference "alias": h is a second name
				// for the symlink inode itself, so it reads back as the same
				// symlink AND shares that symlink's inode.
				aliasFi, aerr := os.Lstat(filepath.Join(dir, "alias"))
				if aerr != nil {
					t.Fatalf("Lstat alias: %v", aerr)
				}
				hFi, herr := os.Lstat(filepath.Join(dir, "h"))
				if herr != nil {
					t.Fatalf("Lstat hardlink: %v", herr)
				}
				if hFi.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("h must be a hardlink to the symlink inode (still a symlink), got %v", hFi.Mode())
				}
				if !os.SameFile(aliasFi, hFi) {
					t.Fatal("h and alias must share one inode: a hardlink to the symlink itself, not a fresh symlink")
				}
				if got, rerr := os.Readlink(filepath.Join(dir, "h")); rerr != nil || got != "real" {
					t.Fatalf("h must point at %q, got %q err=%v", "real", got, rerr)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			data := buildTar(t, tc.entries)
			err := Extract(bytes.NewReader(data), dir, DefaultLimits())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("hardlink scenario %s: want error containing %q, got: %v",
						tc.name, tc.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("hardlink scenario %s: Extract must accept this archive, got: %v",
					tc.name, err)
			}
			tc.validate(t, dir)
		})
	}
}
