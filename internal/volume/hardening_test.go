package volume

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateHostPath_SymlinkEscape pins the symlink-resolution fix: a
// path that lexically lives under baseDir but contains a symlink pointing
// outside must be rejected.
func TestValidateHostPath_SymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()

	m := NewManager(base)

	// <base>/evil -> outside
	if err := os.Symlink(outside, filepath.Join(base, "evil")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := m.validateHostPath(filepath.Join(base, "evil", "data")); err == nil {
		t.Fatal("symlink escape through <base>/evil accepted")
	}
	// The symlink itself is also an escape (resolves to `outside`).
	if err := m.validateHostPath(filepath.Join(base, "evil")); err == nil {
		t.Fatal("hostPath equal to an escaping symlink accepted")
	}
}

// TestValidateHostPath_NonExistingTailAccepted keeps the legitimate plugin
// flow working: the path need not exist yet; its existing ancestor chain is
// resolved and the not-yet-created tail appended before the containment
// check.
func TestValidateHostPath_NonExistingTailAccepted(t *testing.T) {
	base := t.TempDir()
	m := NewManager(base)

	p := filepath.Join(base, "not-yet-created", "vol")
	if err := m.validateHostPath(p); err != nil {
		t.Fatalf("legitimate non-existing hostPath rejected: %v", err)
	}

	// ...but a non-existing tail under an escaping symlink is still caught.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "evil2")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := m.validateHostPath(filepath.Join(base, "evil2", "later")); err == nil {
		t.Fatal("non-existing tail under escaping symlink accepted")
	}
}

// TestBinaryPlugin_StdoutCap verifies the 1 MiB stdout cap: a plugin that
// floods stdout fails with an explicit overflow error instead of growing an
// unbounded buffer.
func TestBinaryPlugin_StdoutCap(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "flood.sh")
	body := `#!/bin/sh
dd if=/dev/zero bs=1024 count=2048 2>/dev/null
printf '{"error":""}\n'
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	p := NewBinary("flood", script)
	if err := p.Init(context.Background(), PluginConfig{Name: "flood"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, err := p.Attach(context.Background(), &AttachRequest{VolumeID: "v1"})
	if err == nil || !strings.Contains(err.Error(), "stdout exceeded") {
		t.Fatalf("Attach err = %v, want stdout-cap error", err)
	}
}
