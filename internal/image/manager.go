package image

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"uml-container/internal/filesystem"
)

// Pull downloads an alpine tarball and extracts it into a new ext4 image
func Pull(baseName string) error {
	imgDir := "/var/lib/uml-container/images"
	os.MkdirAll(imgDir, 0755)
	imgPath := filepath.Join(imgDir, baseName+".img")

	if _, err := os.Stat(imgPath); err == nil {
		fmt.Printf("Image %s already exists\n", baseName)
		return nil
	}

	// Create ext4 image
	if err := filesystem.CreateExt4Image(imgPath, 100); err != nil {
		return err
	}

	tarURL := "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz"
	
	mnt := filepath.Join(imgDir, "mnt")
	os.MkdirAll(mnt, 0755)
	
	exec.Command("sudo", "mount", "-o", "loop", imgPath, mnt).Run()
	defer exec.Command("sudo", "umount", mnt).Run()
	
	cmd := exec.Command("sudo", "sh", "-c", fmt.Sprintf("wget -qO- %s | tar -xz -C %s", tarURL, mnt))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to pull and extract: %v", err)
	}

	return nil
}

// CreateLayer prepares the upper and work dirs for a container overlay
func CreateLayer(containerID string) error {
	dir := filepath.Join("/var/lib/uml-container/containers", containerID)
	return filesystem.SetupOverlayfs(dir)
}
