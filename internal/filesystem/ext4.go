package filesystem

import (
	"fmt"
	"os/exec"
)

// CreateExt4Image creates a new file and formats it as ext4.
func CreateExt4Image(path string, sizeMb int) error {
	// Create sparse file or zero-filled
	cmd := exec.Command("dd", "if=/dev/zero", fmt.Sprintf("of=%s", path), "bs=1M", fmt.Sprintf("count=%d", sizeMb))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create image file: %v", err)
	}

	// Format as ext4
	cmd = exec.Command("mkfs.ext4", "-F", path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to format as ext4: %v", err)
	}

	return nil
}
