package image

import (
	"os"
	"path/filepath"
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
	safe := "alpine.img"
	target := filepath.Join(imgDir, safe)
	if err := os.WriteFile(target, []byte("dummy"), 0644); err != nil {
		t.Fatalf("seed image: %v", err)
	}

	if err := Pull(ref); err != nil {
		t.Fatalf("Pull on existing image should be nil, got: %v", err)
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
