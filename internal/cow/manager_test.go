package cow

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeQcow2Base builds a standalone (backing-less) qcow2 image at path using
// the pure-Go writer — no qemu-img binary required.
func makeQcow2Base(t *testing.T, path string) {
	t.Helper()
	if err := createQcow2(path, 1<<20, "", "", OverlayOpt{ClusterBits: 16}); err != nil {
		t.Fatalf("create qcow2 base %s: %v", path, err)
	}
}

// TestCreateOverlay_CorruptQcow2Backing ensures a file that merely STARTS
// with the qcow2 magic but has an invalid header is rejected with a clear
// error instead of producing a broken overlay.
func TestCreateOverlay_CorruptQcow2Backing(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := os.WriteFile(base, append([]byte(qcow2Magic), make([]byte, 1024)...), 0644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	out := filepath.Join(dir, "overlay.qcow2")
	err := CreateOverlay(context.Background(), base, out)
	if err == nil {
		t.Fatal("expected error for corrupt qcow2 backing header")
	}
	if !strings.Contains(err.Error(), "qcow2") {
		t.Errorf("error should mention qcow2, got: %v", err)
	}
}

func TestValidatePath_RejectsComma(t *testing.T) {
	if err := validatePath("/safe/path.img"); err != nil {
		t.Errorf("safe path rejected: %v", err)
	}
	if err := validatePath("/bad/file,opt=evil"); err == nil {
		t.Error("comma path should be rejected (option injection)")
	}
	if err := validatePath(""); err == nil {
		t.Error("empty path should be rejected")
	}
}

// TestCreateOverlay_HappyPath creates a qcow2 base and an overlay, and
// verifies the overlay is itself a real qcow2 (magic header "QFI\xfb").
func TestCreateOverlay_HappyPath(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	makeQcow2Base(t, base)
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("create: %v", err)
	}
	hdr := make([]byte, 4)
	f, err := os.Open(overlay)
	if err != nil {
		t.Fatalf("open overlay: %v", err)
	}
	defer f.Close()
	if _, err := f.Read(hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if string(hdr) != qcow2Magic {
		t.Errorf("overlay is not qcow2 (magic=%q)", string(hdr))
	}
}

func TestCreateOverlay_IdempotentRecreate(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	makeQcow2Base(t, base)
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// taint the overlay. A failure here is fatal: it would mean the test never
	// got to verify that recreate clears stale data, so the assertion below
	// would pass vacuously.
	if err := os.WriteFile(overlay, []byte("stale"), 0644); err != nil {
		t.Fatalf("taint overlay: %v", err)
	}
	// second create should replace, not append/reuse the tainted file
	if err := CreateOverlay(context.Background(), base, overlay); err != nil {
		t.Fatalf("second create: %v", err)
	}
	data, err := os.ReadFile(overlay)
	if err != nil {
		t.Fatalf("read overlay after recreate: %v", err)
	}
	if strings.HasPrefix(string(data), "stale") {
		t.Error("overlay was not replaced on recreate (stale data leaked)")
	}
}

// TestCreateOverlay_AcceptsRawBacking verifies the ubd-compatible path: a
// raw ext4 backing image produces a valid qcow2 overlay (qcow2-over-raw).
// This is what lets the ubd-path base double as a CoW backing image when the
// caller later switches to vhost.
func TestCreateOverlay_AcceptsRawBacking(t *testing.T) {
	dir := t.TempDir()
	rawBase := filepath.Join(dir, "base.img")
	if err := os.WriteFile(rawBase, make([]byte, 1<<20), 0644); err != nil {
		t.Fatalf("write raw base: %v", err)
	}
	overlay := filepath.Join(dir, "ov.qcow2")
	if err := CreateOverlay(context.Background(), rawBase, overlay); err != nil {
		t.Fatalf("CreateOverlay with raw backing should succeed: %v", err)
	}
	// The overlay itself must still be qcow2.
	hdr := make([]byte, 4)
	f, err := os.Open(overlay)
	if err != nil {
		t.Fatalf("open overlay: %v", err)
	}
	defer f.Close()
	if _, err := f.Read(hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if string(hdr) != qcow2Magic {
		t.Errorf("overlay is not qcow2 (magic=%q)", string(hdr))
	}
}

// TestValidatePath_RejectsProtocolSpecifiers covers the image-source
// injection vector: prefixes like json:, nbd://, http:// make qcow2-aware
// consumers treat the "path" as a remote/synthetic image. validatePath must
// refuse them so a crafted backing path cannot pull an attacker-controlled
// image.
func TestValidatePath_RejectsProtocolSpecifiers(t *testing.T) {
	for _, p := range []string{"json:{...}", "nbd://evil:10809/x", "http://evil/y.img", "ssh://evil/z", "HTTPS://evil/z"} {
		if err := validatePath(p); err == nil {
			t.Errorf("validatePath(%q) = nil; want rejection (protocol specifier)", p)
		}
	}
}

// TestValidatePath_RejectsLeadingDash covers the option-injection vector: a
// filename starting with '-' would be parsed as a flag by CLI tools if it
// reached an argv. validatePath must reject it before that.
func TestValidatePath_RejectsLeadingDash(t *testing.T) {
	cases := []struct {
		path string
		want bool // true = should be rejected
	}{
		{"/safe/path.img", false},
		{"./relative.img", false},
		{"-flag", true},
		{"--output=evil", true},
		{"/safe/-flag", false}, // leading '-' only on a non-first element is fine
	}
	for _, c := range cases {
		err := validatePath(c.path)
		if c.want && err == nil {
			t.Errorf("validatePath(%q) = nil; want rejection (option injection)", c.path)
		}
		if !c.want && err != nil {
			t.Errorf("validatePath(%q) = %v; want accept", c.path, err)
		}
	}
}

// TestIsQcow2 covers the magic sniff CreateOverlay uses to pick the backing
// format recorded in the overlay header.
func TestIsQcow2(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.img")
	if err := os.WriteFile(raw, make([]byte, 64), 0644); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	qcow2 := filepath.Join(dir, "ov.qcow2")
	if err := os.WriteFile(qcow2, append([]byte(qcow2Magic), make([]byte, 64)...), 0644); err != nil {
		t.Fatalf("write qcow2: %v", err)
	}
	if isQcow2(raw) {
		t.Error("isQcow2(raw) = true, want false")
	}
	if !isQcow2(qcow2) {
		t.Error("isQcow2(qcow2) = false, want true")
	}
	if isQcow2(filepath.Join(dir, "nope.img")) {
		t.Error("isQcow2(missing) = true, want false")
	}
}

// TestCreateOverlay_RelativeBackingAbsolutized is the regression test for the
// relative-backing-path bug that broke scripts/test_io_perf.sh and
// tests/04_test_qcow2_mount.sh: qcow2 consumers resolve a relative backing
// name against the OVERLAY's directory, not the caller's CWD — so a caller
// that passes a relative base (e.g. `agentpvm run -rootfs base.qcow2`) would
// see <statedir>/<task>/base.qcow2 being opened and fail, even though
// os.Stat found the file in the agentpvm CWD. CreateOverlay absolutizes both
// paths before recording the backing reference.
func TestCreateOverlay_RelativeBackingAbsolutized(t *testing.T) {
	work := t.TempDir()
	baseDir := filepath.Join(work, "cwd")
	overlayDir := filepath.Join(work, "ov")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatalf("mkdir baseDir: %v", err)
	}
	if err := os.MkdirAll(overlayDir, 0755); err != nil {
		t.Fatalf("mkdir overlayDir: %v", err)
	}
	base := filepath.Join(baseDir, "base.qcow2")
	makeQcow2Base(t, base)
	overlay := filepath.Join(overlayDir, "ov.qcow2")

	// Switch CWD so "base.qcow2" resolves relatively; restore on exit.
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(baseDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(origWd)

	// Hand CreateOverlay a RELATIVE base in a different directory from the
	// overlay. The recorded backing name must be absolute so any consumer
	// finds <baseDir>/base.qcow2 regardless of its CWD.
	if err := CreateOverlay(context.Background(), "base.qcow2", overlay); err != nil {
		t.Fatalf("relative backing not absolutized: %v", err)
	}
	// Reopening the overlay must resolve the backing chain successfully —
	// only possible because the recorded backing path is absolute.
	img, err := openGuestImage(overlay)
	if err != nil {
		t.Fatalf("reopen overlay: %v", err)
	}
	defer img.Close()
	if _, ok := img.(*qcow2Image); !ok {
		t.Fatalf("overlay did not parse as qcow2")
	}
	if img.Size() != 1<<20 {
		t.Errorf("overlay virtual size = %d, want %d", img.Size(), 1<<20)
	}
}
