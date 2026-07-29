package snapshot

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

// Export packages a container's state and data into a .tgz archive
func Export(containerID string, destTgz string) error {
	dir := filepath.Join("/var/lib/uml-container/containers", containerID)
	cmd := exec.Command("tar", "-czf", destTgz, "-C", dir, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar export failed: %v, output: %s", err, string(out))
	}
	return nil
}

// Import restores a container from a .tgz archive
func Import(srcTgz string, newContainerID string) error {
	dir := filepath.Join("/var/lib/uml-container/containers", newContainerID)
	exec.Command("mkdir", "-p", dir).Run()
	
	cmd := exec.Command("tar", "-xzf", srcTgz, "-C", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar import failed: %v, output: %s", err, string(out))
	}
	return nil
}
