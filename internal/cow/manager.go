package cow

import (
	"fmt"
	"os/exec"
)

// CreateOverlay creates a Copy-on-Write overlay image using qcow2.
// This is the magic trick: it doesn't require the host to use btrfs/ZFS.
// qcow2 handles the CoW mechanism entirely in user-space/storage layer.
func CreateOverlay(backingFile string, overlayFile string, backingFormat string) error {
	if backingFormat == "" {
		backingFormat = "raw" // Default to raw ext4 image if not specified
	}
	// qemu-img create -f qcow2 -b <base> -F <format> <overlay>
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2", "-b", backingFile, "-F", backingFormat, overlayFile)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create qcow2 overlay: %v", err)
	}
	return nil
}
