package image

import (
	"fmt"
	"io"
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

	// Build on a temporary path and rename into place only after success, so a
	// crashed/partial extraction can never be mistaken for a complete image on
	// the next run (the Stat fast-path above would otherwise reuse it).
	tmpImg, err := os.CreateTemp(imgDir, safeName+"-*.img.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp image file: %v", err)
	}
	tmpImgPath := tmpImg.Name()
	// Whatever happens below, never leave a .tmp behind on failure.
	cleanup := func() {
		tmpImg.Close()
		os.Remove(tmpImgPath)
	}
	tmpImg.Close()

	// Create ext4 image (500MB default)
	if err := filesystem.CreateExt4Image(tmpImgPath, 500); err != nil {
		cleanup()
		return err
	}

	mnt, err := os.MkdirTemp(imgDir, "mnt-"+safeName+"-*")
	if err != nil {
		cleanup()
		return fmt.Errorf("failed to create temp mount dir: %v", err)
	}
	defer os.RemoveAll(mnt)

	mounted := false
	if err := exec.Command("sudo", "mount", "-o", "loop", tmpImgPath, mnt).Run(); err != nil {
		cleanup()
		return fmt.Errorf("failed to mount image: %v", err)
	}
	mounted = true
	// Ensure umount runs before cleanup removes the mountpoint. Ignore umount
	// errors but always attempt it so we don't leave a busy mount behind.
	defer func() {
		if mounted {
			exec.Command("sudo", "umount", mnt).Run()
		}
	}()

	fmt.Printf("Exporting docker image %s...\n", imageRef)

	img, err := crane.Pull(imageRef)
	if err != nil {
		cleanup()
		return fmt.Errorf("crane pull failed: %v", err)
	}

	f, err := os.CreateTemp(imgDir, "temp-"+safeName+"-*.tar")
	if err != nil {
		cleanup()
		return fmt.Errorf("failed to create temp tar file: %v", err)
	}
	tarFile := f.Name()
	defer os.Remove(tarFile)

	if err := crane.Export(img, f); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("crane export failed: %v", err)
	}
	f.Close()

	cmd := exec.Command("sudo", "tar", "-xf", tarFile, "-C", mnt)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return fmt.Errorf("failed to extract tar: %v, out: %s", err, string(out))
	}

	// Atomically publish the finished image. os.Rename is atomic on the same
	// filesystem (imgDir is the parent of tmpImgPath).
	if err := os.Rename(tmpImgPath, imgPath); err != nil {
		cleanup()
		return fmt.Errorf("failed to publish image: %v", err)
	}

	return nil
}

func CreateLayer(containerID string) error {
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return err
	}
	return filesystem.SetupOverlayfs(dir)
}

// MountLayer historically mounted a host overlay at <dir>/merged and returned,
// expecting the caller to pass that directory as the UML rootfs. That contract
// is broken: UML's ubd0= expects a block image file, not a host directory, so
// root=/dev/ubda could never see the overlay contents.
//
// To keep the overlay semantics (writable layer over a read-only base image)
// while giving UML a real block image, we instead synthesize a fresh ext4
// image that contains a copy of the base image's contents, plus an empty
// "upper" area, and return its path. The guest mounts overlay inside itself.
// For simplicity (and because the guest already has overlayfs enabled per
// scripts/build_kernel.sh CONFIG_OVERLAY_FS) we also accept the simpler model
// where the synthesized image is fully writable and the guest uses it directly
// as root=/dev/ubda -- no in-guest overlay mount required.
func MountLayer(containerID, rootfs string) (string, error) {
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return "", err
	}

	// Resolve base image. If rootfs points at our image store (.img), use it;
	// otherwise treat it as a path the caller already arranged.
	baseImg := rootfs
	if _, err := os.Stat(baseImg); err != nil {
		return "", fmt.Errorf("overlay base image not found: %s", baseImg)
	}

	// Create a writable copy of the base image as the container's root disk.
	mergedImg := filepath.Join(dir, "rootfs.img")
	if err := copyFile(baseImg, mergedImg); err != nil {
		return "", fmt.Errorf("failed to clone base image: %v", err)
	}
	return mergedImg, nil
}

// copyFile copies src to dst byte-for-byte. Used to materialize a writable
// per-container root image from a read-only base image.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
