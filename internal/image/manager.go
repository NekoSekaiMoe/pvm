package image

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"uml-container/internal/filesystem"

	"github.com/google/go-containerregistry/pkg/crane"
)

// Pull downloads an image (either Docker or tarball) and extracts it into a new ext4 image
func Pull(imageRef string) error {
	imgDir := "/var/lib/uml-container/images"
	os.MkdirAll(imgDir, 0755)
	
	// Format name
	safeName := strings.ReplaceAll(imageRef, "/", "_")
	safeName = strings.ReplaceAll(safeName, ":", "_")
	imgPath := filepath.Join(imgDir, safeName+".img")

	if _, err := os.Stat(imgPath); err == nil {
		fmt.Printf("Image %s already exists\n", imageRef)
		return nil
	}

	// Create ext4 image (500MB default)
	if err := filesystem.CreateExt4Image(imgPath, 500); err != nil {
		return err
	}

	mnt := filepath.Join(imgDir, "mnt")
	os.MkdirAll(mnt, 0755)

	exec.Command("sudo", "mount", "-o", "loop", imgPath, mnt).Run()
	defer exec.Command("sudo", "umount", mnt).Run()

	fmt.Printf("Exporting docker image %s...\n", imageRef)
	// Pull from docker registry and extract to mnt
	tarFile := filepath.Join(imgDir, "temp.tar")
	
	img, err := crane.Pull(imageRef)
	if err != nil {
		return fmt.Errorf("crane pull failed: %v", err)
	}

	f, err := os.Create(tarFile)
	if err != nil {
		return fmt.Errorf("failed to create tar file: %v", err)
	}
	if err := crane.Export(img, f); err != nil {
		f.Close()
		return fmt.Errorf("crane export failed: %v", err)
	}
	f.Close()
	defer os.Remove(tarFile)

	cmd := exec.Command("sudo", "tar", "-xf", tarFile, "-C", mnt)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract tar: %v", err)
	}

	return nil
}

func CreateLayer(containerID string) error {
	dir := filepath.Join("/var/lib/uml-container/containers", containerID)
	return filesystem.SetupOverlayfs(dir)
}
