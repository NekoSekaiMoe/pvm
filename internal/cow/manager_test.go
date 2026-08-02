package cow

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// makeQcow2Base builds a real qcow2 file at path using qemu-img, skipping the
// test when qemu-img is unavailable. The agent path is qcow2-only, so every
// CreateOverlay test needs a qcow2 (not raw) backing image.
func makeQcow2Base(t *testing.T, path string) {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	if out, err := exec.Command("qemu-img", "create", "-f", "qcow2", path, "1M").CombinedOutput(); err != nil {
		t.Fatalf("create qcow2 base %s: %v: %s", path, err, string(out))
	}
}

func TestCreateOverlay_QemuImgMissing(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err == nil {
		t.Skip("qemu-img installed; cannot exercise missing-binary path")
	}
	// Use a REAL qcow2-magic backing file so the only failure mode is the
	// missing qemu-img binary, not a pre-flight validatePath/isQcow2/os.Stat
	// error. A prior version pointed at a raw file or "/nonexistent/base.img",
	// which meant those guards rejected the path before qemu-img was consulted.
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := os.WriteFile(base, append([]byte(qcow2Magic), make([]byte, 1024)...), 0644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	out := filepath.Join(dir, "overlay.qcow2")
	if err := CreateOverlay(context.Background(), base, out); err == nil {
		t.Fatal("expected error when qemu-img missing")
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

// TestCreateOverlay_RealQemu exercises the happy path when qemu-img exists.
// It creates a tiny qcow2 base, makes an overlay, and verifies the overlay is
// itself a real qcow2 (magic header "QFI\xfb").
func TestCreateOverlay_RealQemu(t *testing.T) {
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

// TestCreateOverlay_RejectsRawBacking locks in the qcow2-only contract: a raw
// backing image is rejected with a clear error rather than producing an overlay
// the guest could never mount via vhost-user-blk's qcow2 driver.
func TestCreateOverlay_RejectsRawBacking(t *testing.T) {
	dir := t.TempDir()
	rawBase := filepath.Join(dir, "base.img")
	if err := os.WriteFile(rawBase, make([]byte, 1<<20), 0644); err != nil {
		t.Fatalf("write raw base: %v", err)
	}
	overlay := filepath.Join(dir, "ov.qcow2")
	err := CreateOverlay(context.Background(), rawBase, overlay)
	if err == nil {
		t.Fatal("expected error for raw backing image")
	}
	if !strings.Contains(err.Error(), "not qcow2") {
		t.Errorf("expected a 'not qcow2' error, got: %v", err)
	}
}

// TestValidatePath_RejectsProtocolSpecifiers covers the qemu-img image-source
// injection vector: prefixes like json:, nbd://, http:// make qemu-img treat
// the "path" as a remote/synthetic image. validatePath must refuse them so a
// crafted backing path cannot pull an attacker-controlled image.
func TestValidatePath_RejectsProtocolSpecifiers(t *testing.T) {
	for _, p := range []string{"json:{...}", "nbd://evil:10809/x", "http://evil/y.img", "ssh://evil/z", "HTTPS://evil/z"} {
		if err := validatePath(p); err == nil {
			t.Errorf("validatePath(%q) = nil; want rejection (protocol specifier)", p)
		}
	}
}

// TestValidatePath_RejectsLeadingDash covers the option-injection vector: a
// filename starting with '-' would be parsed by qemu-img as a flag if it
// reached the argv. validatePath must reject it before that.
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

// TestIsQcow2 covers the magic sniff CreateOverlay uses to enforce the
// qcow2-only backing contract.
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
// qemu-img relative-backing-path bug that broke scripts/test_io_perf.sh and
// tests/04_test_qcow2_mount.sh. qemu-img resolves a relative -b backing path
// against the OVERLAY's directory, not the caller's CWD — so a caller that
// passes a relative base (e.g. `agentpvm run -rootfs base.qcow2`) would see
// qemu-img look for <statedir>/<task>/base.qcow2 and fail, even though os.Stat
// found the file in the agentpvm CWD. CreateOverlay now absolutizes both paths
// before invoking qemu-img.
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
	// overlay. Pre-fix this failed with "Could not open '<overlayDir>/base.qcow2'";
	// post-fix the absolute resolution makes qemu-img find <baseDir>/base.qcow2.
	if err := CreateOverlay(context.Background(), "base.qcow2", overlay); err != nil {
		t.Fatalf("relative backing not absolutized (qemu-img looked in the overlay dir): %v", err)
	}
}
