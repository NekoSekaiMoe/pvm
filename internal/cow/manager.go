// Package cow implements block-level Copy-on-Write overlays using qcow2.
//
// Design (plan.md §5.2): N sandboxes share a single read-only base image
// (the immutable toolchain + repo snapshot). Each sandbox gets its own qcow2
// overlay backed by that base; all writes diverge into the overlay. The base
// never changes, so cache/share is safe across tenants.
//
// This package is qcow2-ONLY, by deliberate choice:
//   - The sole block backend on the agent path is qemu-storage-daemon via
//     vhost-user-blk, which reads qcow2. UML's built-in ubd reads raw bytes
//     and cannot mount a qcow2 image — so a raw backing image is rejected at
//     CreateOverlay rather than failing later as an opaque guest
//     "VFS: Unable to mount root fs" panic. Callers with a raw image must
//     convert it first (`qemu-img convert -O qcow2 raw.img base.qcow2`).
//   - qemu-storage-daemon already serves qcow2 via vhost-user-blk, so the
//     overlay plugs straight into the existing storage path.
//
// The previous host-side overlayfs-on-a-directory approach was broken: UML
// consumes a block device, so a directory rootfs could never be seen by the
// guest kernel. qcow2 fixes that at the storage layer.
package cow

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// qcow2Magic is the first 4 bytes of every qcow2 image ("QFI\xfb").
const qcow2Magic = "QFI\xfb"

// CreateOverlay creates a qcow2 overlay backed by baseImage. The base is
// treated as read-only by qemu; only overlayFile receives writes.
//
// The backing image MUST itself be qcow2 (see the package doc for why raw is
// not supported). CreateOverlay sniffs the backing magic and rejects a
// non-qcow2 base with a clear error.
//
// The ctx bounds how long the synchronous qemu-img invocation may run; a
// hung backing store cannot block the caller indefinitely. A nil ctx is
// treated as context.Background().
func CreateOverlay(ctx context.Context, baseImage, overlayFile string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, qemuTimeout)
	defer cancel()
	if baseImage == "" || overlayFile == "" {
		return errors.New("cow: base and overlay paths required")
	}
	// Validate BOTH paths before touching the filesystem. validatePath is the
	// only guard against qemu-img option/protocol injection (commas, leading
	// '-', and remote-image specifiers like json:/nbd://), so it must run on
	// baseImage and overlayFile before os.Stat / os.MkdirAll / qemu-img.
	if err := validatePath(baseImage); err != nil {
		return err
	}
	if err := validatePath(overlayFile); err != nil {
		return err
	}
	// Resolve both paths to ABSOLUTE before handing them to qemu-img. qemu-img
	// resolves a relative backing file (-b) against the OVERLAY's directory,
	// not the caller's CWD — so a relative base that os.Stat happily finds in
	// the agentpvm CWD would make qemu-img look for <statedir>/<task>/<base>
	// and fail. Absolutizing here makes the backing path unambiguous.
	absBase, err := filepath.Abs(baseImage)
	if err != nil {
		return fmt.Errorf("cow: resolve backing path: %w", err)
	}
	absOverlay, err := filepath.Abs(overlayFile)
	if err != nil {
		return fmt.Errorf("cow: resolve overlay path: %w", err)
	}
	baseImage, overlayFile = absBase, absOverlay
	if _, err := os.Stat(baseImage); err != nil {
		return fmt.Errorf("cow: backing image not found: %w", err)
	}
	// Enforce qcow2 backing by sniffing the magic, not the extension: qemu-img
	// would otherwise happily accept a raw file with -F qcow2 and produce an
	// overlay whose backing probe fails (or worse, a garbage mount).
	if !isQcow2(baseImage) {
		return fmt.Errorf("cow: backing image %s is not qcow2; convert it with `qemu-img convert -O qcow2` first (raw backing is not supported)", baseImage)
	}
	if err := os.MkdirAll(filepath.Dir(overlayFile), 0755); err != nil {
		return fmt.Errorf("cow: create overlay dir: %w", err)
	}

	// Remove a stale overlay so re-creating after a crash is idempotent. We do
	// NOT silently reuse: a leftover overlay might contain partial writes from
	// a previous, failed task. Explicit recreation = known-good empty state.
	if _, err := os.Stat(overlayFile); err == nil {
		if err := os.Remove(overlayFile); err != nil {
			return fmt.Errorf("cow: remove stale overlay: %w", err)
		}
	}

	// Fixed argument order and "--" so no filename is ever parsed as an option,
	// even if validatePath were bypassed. Both base and overlay are qcow2.
	cmd := exec.CommandContext(ctx, "qemu-img",
		"create", "-f", "qcow2",
		"-b", baseImage,
		"-F", "qcow2",
		"--",
		overlayFile,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cow: qemu-img create failed: %w: %s", err, string(out))
	}
	return nil
}

// isQcow2 reports whether path begins with the qcow2 magic ("QFI\xfb"). A
// missing or unreadable file is treated as "not qcow2" so the caller surfaces
// a clear "convert it first" error instead of a confusing qemu-img failure.
func isQcow2(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := f.Read(hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == qcow2Magic
}

// CommitOverlay merges an overlay back into a new full image (leaving the
// original base untouched). Used when a task's output should be captured as a
// standalone artifact (plan.md §5.3 Artifact = declared output only).
func CommitOverlay(ctx context.Context, overlayFile, destImage string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, qemuTimeout)
	defer cancel()
	if err := validatePath(overlayFile); err != nil {
		return err
	}
	if err := validatePath(destImage); err != nil {
		return err
	}
	// Absolutize for consistency with CreateOverlay: qemu-img resolves paths
	// relative to its own CWD, and a relative destImage passed to MkdirAll
	// would create dirs under the caller CWD rather than where the caller
	// intended when CWD changed between validation and exec.
	if abs, err := filepath.Abs(overlayFile); err == nil {
		overlayFile = abs
	}
	if abs, err := filepath.Abs(destImage); err == nil {
		destImage = abs
	}
	if err := os.MkdirAll(filepath.Dir(destImage), 0755); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "qemu-img", "convert", "-O", "raw", "--", overlayFile, destImage)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cow: convert failed: %w: %s", err, string(out))
	}
	return nil
}

// qemuTimeout bounds every qemu-img invocation so a hung backing store can't
// block the task startup path indefinitely.
var qemuTimeout = 2 * time.Minute

// validatePath rejects empty, comma-bearing, NUL-bearing and option/protocol
// injection patterns. Commas delimit qemu-img options; a leading '-' would let
// a filename pose as a flag; and qemu-img interprets several prefixes (json:,
// nbd://, http://, ...) as remote/spec image sources rather than local files —
// we refuse any of those so an untrusted path can never be parsed as a remote
// backing image.
func validatePath(p string) error {
	if p == "" {
		return errors.New("cow: empty path")
	}
	if strings.ContainsAny(p, ",\x00") {
		return fmt.Errorf("cow: path %q contains forbidden sequence (comma or NUL)", p)
	}
	// A leading '-' turns a filename into a flag for many tools; reject it.
	// Absolute/relative paths like "./foo" are allowed as long as the first
	// path element doesn't start with '-'.
	first := p
	if idx := strings.IndexByte(p, '/'); idx >= 0 {
		first = p[:idx]
	}
	if strings.HasPrefix(first, "-") {
		return fmt.Errorf("cow: path %q starts with '-' (option injection)", p)
	}
	// qemu-img accepts protocol/specifier prefixes (json:, nbd+tcp://, http://,
	// ssh://, ...) that point at remote or synthetic image sources. They are
	// recognized case-insensitively and may carry a scheme before any '/'.
	for _, pref := range []string{"json:", "nbd", "http://", "https://", "ftp://", "ssh://", "gluster://", "iscsi://"} {
		if strings.HasPrefix(strings.ToLower(p), pref) {
			return fmt.Errorf("cow: path %q looks like a qemu-img image specifier (remote/protocol prefix forbidden)", p)
		}
	}
	return nil
}
