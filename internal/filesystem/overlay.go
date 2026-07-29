package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
)

// SetupOverlayfs prepares the directories for overlayfs mounting inside UML.
// In this design, overlayfs is actually mounted by the guest, but we prepare the directories on host.
func SetupOverlayfs(baseDir string) error {
	dirs := []string{"upper", "work", "merged"}
	for _, d := range dirs {
		p := filepath.Join(baseDir, d)
		if err := os.MkdirAll(p, 0755); err != nil {
			return fmt.Errorf("failed to create overlay dir %s: %v", p, err)
		}
	}
	return nil
}
