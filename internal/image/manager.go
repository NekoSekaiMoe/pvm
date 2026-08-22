package image

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"uml-container/internal/filesystem"
	"uml-container/internal/state"
	"uml-container/internal/tarutil"

	"github.com/google/go-containerregistry/pkg/crane"
)

// defaultRegistryAllowlist is used when PVM_REGISTRY_ALLOWLIST is unset.
// localhost/127.0.0.1 (any port) are included so local development registries
// keep working; "*" anywhere in the list allows everything.
const defaultRegistryAllowlist = "docker.io,ghcr.io,gcr.io,quay.io,registry.k8s.io,localhost:*,127.0.0.1:*,[::1]:*"

// registryAllowed reports whether imageRef's registry is on the configured
// allowlist (env PVM_REGISTRY_ALLOWLIST, comma-separated hosts, optionally
// with a ":port" or ":*" suffix; "*" allows all).
func registryAllowed(imageRef string) bool {
	spec := os.Getenv("PVM_REGISTRY_ALLOWLIST")
	if spec == "" {
		spec = defaultRegistryAllowlist
	}
	if spec == "*" {
		return true
	}
	reg := registryHost(imageRef)
	regHost, _ := splitHostPortRight(reg)
	for _, ent := range strings.Split(spec, ",") {
		ent = strings.TrimSpace(ent)
		if ent == "" {
			continue
		}
		if ent == "*" {
			return true
		}
		// Split entry and reference from the RIGHT so a bracketed IPv6 host
		// ("[::1]:*" / "[::1]:5000") keeps its colons intact in the host part.
		entHost, entPort := splitHostPortRight(ent)
		if entPort == "*" {
			// Wildcard-port entry like "localhost:*" or "[::1]:*": match that
			// host with an explicit port OR with no port at all.
			if entHost == regHost {
				return true
			}
		}
		if ent == reg || strings.Trim(ent, "[]") == strings.Trim(reg, "[]") {
			return true
		}
	}
	return false
}

// splitHostPortRight splits "host:port" at the RIGHTMOST valid port suffix.
// A suffix counts as a port only when it is "*" or all digits, so bare IPv6
// hosts and registry names with colons elsewhere are left intact; bracketed
// IPv6 forms ("[::1]:5000") split cleanly regardless.
func splitHostPortRight(s string) (host, port string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, ""
	}
	suffix := s[i+1:]
	if suffix == "" || suffix == "*" {
		return s[:i], suffix
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return s, "" // not a port suffix; the whole string is the host
		}
	}
	return s[:i], suffix
}

// registryHost extracts the registry host from an OCI image reference.
// Per the distribution-spec convention, the component before the first "/"
// is a registry only when it contains a "." or ":" or equals "localhost";
// otherwise the reference uses the default registry (docker.io).
func registryHost(imageRef string) string {
	i := strings.IndexByte(imageRef, '/')
	if i < 0 {
		// No slash: the whole ref is <repo>[:<tag>] against the default
		// registry ("alpine" -> docker.io/library/alpine). A bare host would
		// name no repository and cannot be pulled.
		return "docker.io"
	}
	first := imageRef[:i]
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return "docker.io"
}

// imageName maps an image reference to its on-disk file name. The raw ref
// cannot be used directly (two different refs can sanitize to the same name:
// "a/b:1" and "a_b_1" would both become a_b_1.img), so the store name is the
// SHA-256 of the reference — collision-free by construction. The original
// reference stays visible in logs.
func imageName(imageRef string) string {
	sum := sha256.Sum256([]byte(imageRef))
	return hex.EncodeToString(sum[:]) + ".img"
}

// DefaultDir is the on-disk root under which pulled images live. The API
// layer constrains caller-supplied rootfs paths to this tree.
const DefaultDir = "/var/lib/uml-container/images"

// Pull downloads an image (either Docker or tarball) and extracts it into a new ext4 image
func Pull(imageRef string) error {
	// Registry allowlist: refuse references outside the configured set before
	// any network or disk activity.
	if !registryAllowed(imageRef) {
		return fmt.Errorf("image %q: registry %q is not on the allowlist (PVM_REGISTRY_ALLOWLIST)", imageRef, registryHost(imageRef))
	}
	imgDir := DefaultDir
	os.MkdirAll(imgDir, 0755)

	// Collision-free store name: sha256(imageRef). See imageName.
	safeName := strings.TrimSuffix(imageName(imageRef), ".img")
	imgPath := filepath.Join(imgDir, imageName(imageRef))

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

	// Extract the exported layer tarball with the hardened tarutil extractor
	// instead of `sudo tar -xf`: traversal/symlink/device-node members are
	// rejected, special permission bits are stripped, and resource limits bound
	// a malicious archive. No root helper is involved in extraction.
	tf, err := os.Open(tarFile)
	if err != nil {
		cleanup()
		return fmt.Errorf("failed to open layer tar: %v", err)
	}
	if err := tarutil.Extract(tf, mnt, tarutil.DefaultLimits()); err != nil {
		tf.Close()
		cleanup()
		return fmt.Errorf("failed to extract tar: %v", err)
	}
	tf.Close()

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
