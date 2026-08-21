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

	// Create sparse file or zero-filled
	cmd := exec.Command("dd", "if=/dev/zero", fmt.Sprintf("of=%s", path), "bs=1M", fmt.Sprintf("count=%d", sizeMb))
	if err := cmd.Run(); err != nil {
		os.Remove(path)
		return fmt.Errorf("failed to create image file: %v", err)
	}

	// Format as ext4
	cmd = exec.Command("mkfs.ext4", "-F", path)
	if err := cmd.Run(); err != nil {
		os.Remove(path)
		return fmt.Errorf("failed to format as ext4: %v", err)
	}

	return nil
}
