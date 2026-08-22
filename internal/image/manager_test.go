package image

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uml-container/internal/state"
)

func TestPull_AlreadyExistsShortCircuits(t *testing.T) {
	// Point the image store at a tmp dir and pre-create the target .img so
	// Pull's existence fast-path returns nil without touching the network.
	root := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = root
	defer func() { state.RootDir = origRoot }()

	// imgDir is hardcoded inside Pull; mirror it.
	imgDir := "/var/lib/uml-container/images"
	if err := os.MkdirAll(imgDir, 0755); err != nil {
		t.Skipf("cannot create %s without root: %v", imgDir, err)
	}
	defer os.RemoveAll(imgDir)

	const ref = "alpine"
	target := filepath.Join(imgDir, imageName(ref))
	if err := os.WriteFile(target, []byte("dummy"), 0644); err != nil {
		t.Fatalf("seed image: %v", err)
	}

	if err := Pull(ref); err != nil {
		t.Fatalf("Pull on existing image should be nil, got: %v", err)
	}
}

func TestRegistryAllowlist(t *testing.T) {
	tests := []struct {
		env  string
		ref  string
		want bool
	}{
		{"", "alpine:3.19", true},                               // default registry docker.io
		{"", "docker.io/library/alpine:3", true},                //
		{"", "ghcr.io/org/img:v1", true},                        //
		{"", "evil.example.com/img:latest", false},              // not on default list
		{"", "127.0.0.1:5000/foo:bar", true},                    // local dev registries allowed by default
		{"", "localhost:9000/foo:bar", true},                    //
		{"*", "anything.example.com/x", true},                   // explicit wildcard
		{"docker.io", "ghcr.io/a/b", false},                     // restrictive override
		{"docker.io,localhost:*", "localhost:5000/a", true},     // wildcard port entry
		{"docker.io,localhost:5000", "localhost:5001/a", false}, // exact port mismatch
		{"docker.io,localhost:*", "localhost/a", true},          // wildcard port matches portless host too
		{"docker.io,[::1]:*", "[::1]:5000/a", true},             // bracketed IPv6, explicit port
		{"docker.io,[::1]:*", "[::1]/a", true},                  // bracketed IPv6, no port
		{"docker.io,127.0.0.1:*", "127.0.0.1/a", true},          // wildcard port, portless ref
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d: env=%s ref=%s want=%v", i, tc.env, tc.ref, tc.want), func(t *testing.T) {
			if tc.env == "" {
				t.Setenv("PVM_REGISTRY_ALLOWLIST", "")
				os.Unsetenv("PVM_REGISTRY_ALLOWLIST")
			} else {
				t.Setenv("PVM_REGISTRY_ALLOWLIST", tc.env)
			}
			if got := registryAllowed(tc.ref); got != tc.want {
				t.Errorf("registryAllowed(%q) with env %q = %v, want %v", tc.ref, tc.env, got, tc.want)
			}
		})
	}
}

func TestImageName_IsCollisionFreeSha256(t *testing.T) {
	a := imageName("a/b:1")
	b := imageName("a_b_1")
	if a == b {
		t.Fatalf("imageName collision: %q == %q", a, b)
	}
	// Old sanitizer collapsed both refs to the same name; sha256 naming must
	// be stable per ref and hex-only.
	if a != imageName("a/b:1") {
		t.Fatal("imageName must be deterministic")
	}
	if len(a) != 64+4 || !strings.HasSuffix(a, ".img") || strings.ContainsAny(a[:64], "/_:") {
		t.Fatalf("unexpected name format: %q", a)
	}
}

func TestPull_RejectsNonAllowlistedRegistry(t *testing.T) {
	t.Setenv("PVM_REGISTRY_ALLOWLIST", "docker.io")
	err := Pull("evil.example.com/img:v1")
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("expected allowlist rejection, got: %v", err)
	}
}

func TestUnusedTempPath_DoesNotCreateFile(t *testing.T) {
	// Pull must hand CreateExt4Image a path that does not exist yet so the
	// image's O_CREATE|O_EXCL reservation actually owns the name; a
	// pre-created file would make that open fail with EEXIST.
	dir := t.TempDir()
	p, err := unusedTempPath(dir, "img-", ".img.tmp")
	if err != nil {
		t.Fatalf("unusedTempPath: %v", err)
	}
	if filepath.Dir(p) != dir {
		t.Fatalf("path %q is not under %s", p, dir)
	}
	base := filepath.Base(p)
	if !strings.HasPrefix(base, "img-") || !strings.HasSuffix(base, ".img.tmp") {
		t.Fatalf("unexpected temp name shape: %q", base)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("unusedTempPath must not create the file; stat err = %v", err)
	}
	// Allocations must not repeat (advisory uniqueness; O_EXCL inside
	// CreateExt4Image remains the authoritative guard).
	p2, err := unusedTempPath(dir, "img-", ".img.tmp")
	if err != nil {
		t.Fatalf("unusedTempPath (second call): %v", err)
	}
	if p2 == p {
		t.Fatalf("two allocations returned the same path %q", p)
	}
}

// writeTar builds a tarball from the given headers (regular-file members get
// a small payload) and returns its path, for checkTarEntryTypes tests.
func writeTar(t *testing.T, headers []*tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "layer.tar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar: %v", err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, hdr := range headers {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", hdr.Name, err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("payload")); err != nil {
				t.Fatalf("write payload for %q: %v", hdr.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return path
}

func TestCheckTarEntryTypes(t *testing.T) {
	// The supported member set mirrors what tarutil.Extract handles.
	supported := []*tar.Header{
		{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "etc/file.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len("payload"))},
		{Name: "etc/link", Typeflag: tar.TypeSymlink, Linkname: "file.txt"},
		{Name: "etc/hard", Typeflag: tar.TypeLink, Linkname: "etc/file.txt"},
		{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader},
	}
	tests := []struct {
		name    string
		headers []*tar.Header
		wantErr string // empty means success expected
	}{
		{name: "supported members pass", headers: supported},
		{
			name: "fifo rejected",
			headers: append(append([]*tar.Header{}, supported...), &tar.Header{
				Name: "run/pipe", Typeflag: tar.TypeFifo,
			}),
			wantErr: "run/pipe",
		},
		{
			name: "char device rejected",
			headers: append(append([]*tar.Header{}, supported...), &tar.Header{
				Name: "dev/nullc", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3,
			}),
			wantErr: "dev/nullc",
		},
		{
			name: "block device rejected",
			headers: append(append([]*tar.Header{}, supported...), &tar.Header{
				Name: "dev/sdab", Typeflag: tar.TypeBlock, Devmajor: 8, Devminor: 0,
			}),
			wantErr: "dev/sdab",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTarEntryTypes(writeTar(t, tc.headers))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkTarEntryTypes: unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected rejection of special entry, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error should name the offending entry %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestMountLayer_ClonesBaseImage(t *testing.T) {
	root := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = root
	defer func() { state.RootDir = origRoot }()

	const id = "c-clone"
	// Create a fake base "image".
	baseDir := filepath.Join(root, id)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	base := filepath.Join(baseDir, "base.img")
	payload := []byte("BASE-CONTENTS")
	if err := os.WriteFile(base, payload, 0644); err != nil {
		t.Fatalf("seed base: %v", err)
	}

	out, err := MountLayer(id, base)
	if err != nil {
		t.Fatalf("MountLayer: %v", err)
	}
	if out == "" {
		t.Fatal("MountLayer returned empty path")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read clone: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("clone contents = %q, want %q", got, payload)
	}
	// Must be a separate file (writable copy), not the base itself.
	if out == base {
		t.Errorf("MountLayer returned the base path; must return a copy")
	}
}

func TestMountLayer_MissingBaseImage(t *testing.T) {
	root := t.TempDir()
	origRoot := state.RootDir
	state.RootDir = root
	defer func() { state.RootDir = origRoot }()

	const id = "c-missing"
	if _, err := MountLayer(id, filepath.Join(root, "nope.img")); err == nil {
		t.Fatalf("expected error for missing base image, got nil")
	}
}
