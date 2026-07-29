package image

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"uml-container/internal/filesystem"
	"uml-container/internal/state"

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

	mnt, err := os.MkdirTemp(imgDir, "mnt-"+safeName+"-*")
	if err != nil {
		return fmt.Errorf("failed to create temp mount dir: %v", err)
	}
	defer os.RemoveAll(mnt)

	if err := exec.Command("sudo", "mount", "-o", "loop", imgPath, mnt).Run(); err != nil {
		return fmt.Errorf("failed to mount image: %v", err)
	}
	defer exec.Command("sudo", "umount", mnt).Run()

	fmt.Printf("Exporting docker image %s...\n", imageRef)
	
	img, err := crane.Pull(imageRef)
	if err != nil {
		return fmt.Errorf("crane pull failed: %v", err)
	}

	f, err := os.CreateTemp(imgDir, "temp-"+safeName+"-*.tar")
	if err != nil {
		return fmt.Errorf("failed to create temp tar file: %v", err)
	}
	tarFile := f.Name()
	defer os.Remove(tarFile)
	
	if err := crane.Export(img, f); err != nil {
		f.Close()
		return fmt.Errorf("crane export failed: %v", err)
	}
	f.Close()

	cmd := exec.Command("sudo", "tar", "-xf", tarFile, "-C", mnt)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract tar: %v", err)
	}

	return nil
}

func CreateLayer(containerID string) error {
	dir := state.ContainerDir(containerID)
	return filesystem.SetupOverlayfs(dir)
}

func MountLayer(containerID, rootfs string) error {
	dir := state.ContainerDir(containerID)
	lower := rootfs
	upper := filepath.Join(dir, "upper")
	work := filepath.Join(dir, "work")
	merged := filepath.Join(dir, "merged")
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	
	cmd := exec.Command("sudo", "mount", "-t", "overlay", "overlay", "-o", opts, merged)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("overlay mount failed: %v, out: %s", err, string(out))
	}
	return nil
}
