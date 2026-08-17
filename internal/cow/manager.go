// Package cow implements block-level Copy-on-Write overlays using qcow2.
//
// Design (plan.md §5.2): N sandboxes share a single read-only base image
// (the immutable toolchain + repo snapshot). Each sandbox gets its own qcow2
// overlay backed by that base; all writes diverge into the overlay. The base
// never changes, so cache/share is safe across tenants.
//
// The OVERLAY is always qcow2. The BACKING image may be either raw or qcow2;
// CreateOverlay sniffs the magic and records the right backing format.
// This matches the two real callers: the vhost path serves the qcow2 overlay
// via qemu-storage-daemon over vhost-user-blk, while the ubd path mounts the
// base directly (no overlay). ubd cannot read qcow2, so a qcow2 base on the
// ubd path panics with "VFS: Unable to mount root fs" — callers that want
// ubd must hand CreateOverlay a raw base.
//
// qcow2 create/convert are implemented in pure Go (qcow2.go); no qemu-img
// binary is required at runtime.
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
	"path/filepath"
	"strings"
)

// qcow2Magic is the first 4 bytes of every qcow2 image ("QFI\xfb").
const qcow2Magic = "QFI\xfb"

// CreateOverlay creates a qcow2 overlay backed by baseImage. The base is
// treated as read-only; only overlayFile receives writes.
//
// The backing image may be raw or qcow2; CreateOverlay sniffs the backing
// magic (not the extension) and records the format in the overlay header, so
// consumers never probe untrusted backing content.
//
// The ctx bounds the (fast, metadata-only) creation; a nil ctx is treated as
// context.Background().
func CreateOverlay(ctx context.Context, baseImage, overlayFile string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if baseImage == "" || overlayFile == "" {
		return errors.New("cow: base and overlay paths required")
	}
	// Validate BOTH paths before touching the filesystem. validatePath is the
	// guard against option/protocol injection patterns (commas, leading '-',
	// remote-image specifiers like json:/nbd://) that qcow2-capable consumers
	// might otherwise interpret.
	if err := validatePath(baseImage); err != nil {
		return err
	}
	if err := validatePath(overlayFile); err != nil {
		return err
	}
	// Resolve both paths to ABSOLUTE before recording the backing reference.
	// qcow2 consumers resolve a relative backing name against the OVERLAY's
	// directory, not the caller's CWD — storing an absolute path makes the
	// reference unambiguous regardless of who opens the overlay from where.
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

	// Sniff the backing format by magic and derive the virtual size from the
	// base: header field for qcow2, file size for raw.
	backing, err := openGuestImage(baseImage)
	if err != nil {
		return fmt.Errorf("cow: open backing image: %w", err)
	}
	virtualSize := backing.Size()
	backing.Close()
	backingFormat := "raw"
	if isQcow2(baseImage) {
		backingFormat = "qcow2"
	}
	return createQcow2(overlayFile, virtualSize, baseImage, backingFormat)
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

// CommitOverlay merges an overlay back into a new full raw image (leaving
// the original base untouched). Used when a task's output should be captured
// as a standalone artifact (plan.md §5.3 Artifact = declared output only).
func CommitOverlay(ctx context.Context, overlayFile, destImage string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validatePath(overlayFile); err != nil {
		return err
	}
	if err := validatePath(destImage); err != nil {
		return err
	}
	// Absolutize for consistency with CreateOverlay: relative paths would
	// resolve against the (possibly changed) caller CWD at MkdirAll time.
	if abs, err := filepath.Abs(overlayFile); err == nil {
		overlayFile = abs
	}
	if abs, err := filepath.Abs(destImage); err == nil {
		destImage = abs
	}
	if err := os.MkdirAll(filepath.Dir(destImage), 0755); err != nil {
		return err
	}
	return convertToRaw(ctx, overlayFile, destImage)
}

// validatePath rejects empty, comma-bearing, NUL-bearing and option/protocol
// injection patterns. Commas delimit image-option syntax for qcow2-aware
// consumers; a leading '-' would let a filename pose as a flag; and remote
// prefixes (json:, nbd://, ...) name remote/synthetic image sources rather
// than local files — we refuse any of those so an untrusted path can never
// be parsed as a remote backing image.
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
