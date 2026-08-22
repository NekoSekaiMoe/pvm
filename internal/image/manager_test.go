package image

import (
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
		{"docker.io,localhost:*", "localhost/a", true},           // wildcard port matches portless host too
		{"docker.io,[::1]:*", "[::1]:5000/a", true},            // bracketed IPv6, explicit port
		{"docker.io,[::1]:*", "[::1]/a", true},                 // bracketed IPv6, no port
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
