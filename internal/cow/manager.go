// Package cow implements block-level Copy-on-Write overlays using qcow2.
//
// Design (plan.md §5.2): N sandboxes share a single read-only base image
// (the immutable toolchain + repo snapshot). Each sandbox gets its own qcow2
// overlay backed by that base; all writes diverge into the overlay. The base
// never changes, so cache/share is safe across tenants.
//
// This is the ONLY CoW mechanism PVM supports, by deliberate choice:
//   - block-level: works with UML's ubd0/vhost-user-blk (which take a block
//     image, not a host directory) without any guest-side configuration;
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

// BackingFormat is the on-disk format of the backing file.
type BackingFormat string

const (
	FormatRaw   BackingFormat = "raw"
	FormatQcow2 BackingFormat = "qcow2"
)

// CreateOverlay creates a qcow2 overlay backed by baseImage. The base is
// treated as read-only by qemu; only overlayFile receives writes.
//
//	backingFormat describes baseImage's format (raw ext4 image by default;
//	use qcow2 if the base is itself a qcow2).
//
// The ctx bounds how long the synchronous qemu-img invocation may run; a
// hung backing store cannot block the caller indefinitely. A nil ctx is
// treated as context.Background().
func CreateOverlay(ctx context.Context, baseImage, overlayFile string, backingFormat BackingFormat) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, qemuTimeout)
	defer cancel()
	if baseImage == "" || overlayFile == "" {
		return errors.New("cow: base and overlay paths required")
	}
	if backingFormat == "" {
		backingFormat = FormatRaw
	}
	if _, err := os.Stat(baseImage); err != nil {
		return fmt.Errorf("cow: backing image not found: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(overlayFile), 0755); err != nil {
		return fmt.Errorf("cow: create overlay dir: %w", err)
	}
	// Reject commas and option-injection patterns in paths. Commas are how
	// qemu-img delimits options, and a leading '-' would let a filename pose
	// as a flag (vhost backend already guards image paths; we guard here too
	// for direct CLI users).
	if err := validatePath(baseImage); err != nil {
		return err
	}
	if err := validatePath(overlayFile); err != nil {
		return err
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
	// even if validatePath were bypassed.
	cmd := exec.CommandContext(ctx, "qemu-img",
		"create", "-f", "qcow2",
		"-b", baseImage,
		"-F", string(backingFormat),
		"--",
		overlayFile,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cow: qemu-img create failed: %w: %s", err, string(out))
	}
	return nil
}

// CreateOverlayTyped is the string-arg shim kept for backward compatibility
// with the old cow.Manager and the `agentpvm cow` CLI.
func CreateOverlayTyped(ctx context.Context, backingFile, overlayFile, backingFormat string) error {
	return CreateOverlay(ctx, backingFile, overlayFile, BackingFormat(backingFormat))
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

// validatePath rejects empty, comma-bearing, NUL-bearing and option-injection
// patterns. Commas delimit qemu-img options; a leading '-' would let a
// filename pose as a flag (defense in depth, even though callers use "--").
func validatePath(p string) error {
	if p == "" {
		return errors.New("cow: empty path")
	}
	for _, bad := range []string{",", "\x00"} {
		if containsByte(p, bad) {
			return fmt.Errorf("cow: path %q contains forbidden sequence %q", p, bad)
		}
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
	return nil
}

func containsByte(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
