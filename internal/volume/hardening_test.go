package volume

import (
	"context"
	"errors"
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
# Flood >1 MiB of stdout using ONLY /bin/sh builtins (printf in a loop):
# no dd/coreutils dependency, so the cap test also runs on minimal hosts.
i=0
while [ "$i" -lt 129 ]; do
	printf '%8192s' ''
	i=$((i+1))
done
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

// TestResolveExisting_LstatErrorPropagates pins the Lstat-error fix in
// resolveExisting: only a genuinely missing component justifies walking up;
// a permission (or other non-ENOENT) error must propagate immediately
// instead of settling on an unresolved path and silently downgrading
// validation to the lexical string-prefix check.
func TestResolveExisting_LstatErrorPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions; Lstat would succeed")
	}
	base := t.TempDir()
	gated := filepath.Join(base, "gated")
	if err := os.Mkdir(gated, 0o000); err != nil {
		t.Fatalf("mkdir gated: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(gated, 0o755) }) // let TempDir cleanup succeed

	// Lstat of <base>/gated/child fails with EACCES (no search on gated).
	// The walk must stop and return the error, not continue up to <base>.
	p := filepath.Join(gated, "child")
	_, err := resolveExisting(p)
	if err == nil {
		t.Fatal("resolveExisting silently accepted a Lstat permission error")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("resolveExisting err = %v, want permission error", err)
	}

	// Through the public validation path the same scenario must be rejected
	// (containment verdict unknown), never fall back to string-prefix checks.
	m := NewManager(base)
	if err := m.validateHostPath(p); err == nil {
		t.Fatal("validateHostPath accepted a path whose ancestors cannot be lstat'd")
	} else if !strings.Contains(err.Error(), "not resolvable") {
		t.Errorf("validateHostPath err = %v, want not-resolvable rejection", err)
	}

	// Sanity: with the gate removed the same path resolves normally.
	if err := os.Chmod(gated, 0o755); err != nil {
		t.Fatalf("chmod gated: %v", err)
	}
	if _, err := resolveExisting(filepath.Join(gated, "child")); err != nil {
		t.Errorf("resolveExisting after chmod: %v", err)
	}
}
