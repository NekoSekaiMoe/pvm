package image

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
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
	// Strip an explicit scheme first: "http://host/img" must yield
	// "host", not "http:" (the first path segment would otherwise look
	// like a registry with a port).
	imageRef = strings.TrimPrefix(strings.TrimPrefix(imageRef, "http://"), "https://")
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

// StorePath returns the on-disk ext4 path a Pull of imageRef produces (or
// would reuse). Template builds bind this path into ImagePath once the
// pull/verify phase completes.
func StorePath(imageRef string) (string, error) {
	if strings.TrimSpace(imageRef) == "" {
		return "", fmt.Errorf("image: empty reference")
	}
	return filepath.Join(DefaultDir, imageName(imageRef)), nil
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
	if err := os.MkdirAll(imgDir, 0755); err != nil {
		return fmt.Errorf("failed to create image directory %s: %v", imgDir, err)
	}

	// Collision-free store name: sha256(imageRef). See imageName.
	safeName := strings.TrimSuffix(imageName(imageRef), ".img")
	imgPath := filepath.Join(imgDir, safeName+".img")

	if _, err := os.Stat(imgPath); err == nil {
		fmt.Printf("Image %s already exists\n", imageRef)
		return nil
	}

	// Everything from here on writes into /var/lib and mounts a loop device
	// (via sudo mount), which requires root. Fail fast with a clear error
	// instead of a confusing mid-pull permission failure. The allowlist and
	// already-exists fast-paths above stay usable unprivileged (unit tests
	// and tests/22 rely on exactly those paths).
	if os.Geteuid() != 0 {
		return fmt.Errorf("image pull of %q requires root (current euid %d); rerun as root or via sudo", imageRef, os.Geteuid())
	}

	// Build on a temporary path and rename into place only after success, so a
	// crashed/partial extraction can never be mistaken for a complete image on
	// the next run (the Stat fast-path above would otherwise reuse it).
	// Pick an unused name WITHOUT creating the file: CreateExt4Image reserves
	// the path atomically via O_CREATE|O_EXCL, and handing it an already-
	// existing file would defeat that non-overwrite guarantee (the open would
	// just fail with EEXIST).
	tmpImgPath, err := unusedTempPath(imgDir, safeName+"-", ".img.tmp")
	if err != nil {
		return fmt.Errorf("failed to allocate temp image path: %v", err)
	}
	// Whatever happens below, never leave a .tmp behind on failure.
	cleanup := func() {
		os.Remove(tmpImgPath)
	}

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

	// Fail-fast disk pre-check (statfs × safety margin): the build's peak
	// usage is base image + layer tar + extracted rootfs; running out mid-
	// pull leaves a half-populated store the rename-fast-path would trust.
	if err := checkDiskHeadroom(imgDir, 500<<20); err != nil {
		cleanup()
		return err
	}

	img, err := crane.Pull(imageRef, cranePullOptions(imageRef)...)
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

	// Pre-check entry types BEFORE extracting anything: tarutil rejects
	// device nodes/FIFOs/special members when it reaches them mid-stream, but
	// by then part of the rootfs has already been written into the mounted
	// image. Walking the tar up front makes the pull fail before any bytes
	// land, with one clear error naming the offending entry. (Implemented in
	// Pull rather than tarutil so the scan precedes the extraction call;
	// tarutil keeps its per-entry defense-in-depth rejection.)
	if err := checkTarEntryTypes(tarFile); err != nil {
		cleanup()
		return fmt.Errorf("refusing to extract image %q: %v", imageRef, err)
	}

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

// unusedTempPath returns a path under dir, shaped prefix+random+suffix, that
// does not currently exist (os.CreateTemp-style naming). Unlike os.CreateTemp
// it does NOT create the file: callers that need atomic ownership take the
// path themselves with O_CREATE|O_EXCL (see filesystem.CreateExt4Image). If
// the name is taken between the check and that open, the open fails cleanly
// with EEXIST, so the existence check here is only advisory.
func unusedTempPath(dir, prefix, suffix string) (string, error) {
	for i := 0; i < 10000; i++ {
		cand := filepath.Join(dir, fmt.Sprintf("%s%d%s", prefix, rand.Int63(), suffix))
		if _, err := os.Lstat(cand); err != nil {
			if os.IsNotExist(err) {
				return cand, nil
			}
			return "", err
		}
	}
	return "", fmt.Errorf("no unused temporary name under %s after 10000 attempts", dir)
}

// checkTarEntryTypes walks the tarball at path and rejects any member whose
// type the extractor does not support: device nodes (char/block), FIFOs, and
// any other special entry. Regular files, directories, symlinks, hardlinks,
// and PAX global headers (archive metadata, skipped by tarutil.Extract) pass.
func checkTarEntryTypes(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open layer tar for entry-type pre-check: %w", err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read layer tar for entry-type pre-check: %w", err)
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeLink, tar.TypeXGlobalHeader:
			// Supported by tarutil.Extract; keep scanning.
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return fmt.Errorf("entry %q is a device node or FIFO (type %d); device/FIFO members are not supported", hdr.Name, hdr.Typeflag)
		default:
			return fmt.Errorf("entry %q has unsupported tar type %d", hdr.Name, hdr.Typeflag)
		}
	}
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
