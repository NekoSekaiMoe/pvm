package filesystem

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// CreateExt4Image creates a new file and formats it as ext4.
func CreateExt4Image(path string, sizeMb int) error {
	// The path becomes a disk image holding a whole rootfs; require an
	// absolute path so a relative name can never silently resolve against a
	// different caller CWD (and to keep the dd/mkfs invocations unambiguous).
	if !filepath.IsAbs(path) {
		return fmt.Errorf("filesystem: image path must be absolute, got %q", path)
	}
	// Pre-create the file with 0600 via O_EXCL: dd writes into an existing
	// file without changing its mode, so without this the image would be
	// created with dd's umask-driven default (typically 0644) — world-readable
	// container contents. O_EXCL also refuses to clobber an existing image.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create image file: %v", err)
	}
	f.Close()

	// Sparse allocation: ftruncate creates a hole-punched file — mkfs.ext4
	// works on it and only the written blocks consume disk (a 500MB base
	// image holding a 40MB rootfs consumes ~40MB, not 500MB). dd was the
	// previous behavior; a fill is only needed for raw device targets, not
	// filesystem images.
	if err := os.Truncate(path, int64(sizeMb)<<20); err != nil {
		os.Remove(path)
		return fmt.Errorf("failed to allocate sparse image %q: %w", path, err)
	}

	// Format as ext4
	mk := exec.Command("mkfs.ext4", "-F", path)
	if err := mk.Run(); err != nil {
		os.Remove(path)
		return fmt.Errorf("failed to format as ext4: %v", err)
	}

	return nil
}
