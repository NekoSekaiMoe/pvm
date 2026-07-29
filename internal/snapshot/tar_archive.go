package snapshot

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"uml-container/internal/state"
)

var validContainerID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Export packages a container's state and data into a .tgz archive
func Export(containerID string, destTgz string) error {
	if !validContainerID.MatchString(containerID) {
		return fmt.Errorf("invalid container ID")
	}
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return err
	}
	cmd := exec.Command("tar", "-czf", destTgz, "-C", dir, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar export failed: %v, output: %s", err, string(out))
	}
	return nil
}

// Import restores a container from a .tgz archive
func Import(srcTgz string, newContainerID string) error {
	if !validContainerID.MatchString(newContainerID) {
		return fmt.Errorf("invalid container ID")
	}

	dir, err := state.ContainerDir(newContainerID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// If any entry fails to extract, remove the half-populated dir so a later
	// import does not silently reuse a corrupted rootfs.
	importOk := false
	defer func() {
		if !importOk {
			os.RemoveAll(dir)
		}
	}()

	f, err := os.Open(srcTgz)
	if err != nil {
		return fmt.Errorf("tar import failed: %v", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("tar import failed: gzip open: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar import failed: tar read: %v", err)
		}

		cleanPath := filepath.Clean(header.Name)
		if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
			return fmt.Errorf("tar import failed: invalid path %s", header.Name)
		}

		target := filepath.Join(dir, cleanPath)
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(filepath.Separator)) && target != filepath.Clean(dir) {
			return fmt.Errorf("tar import failed: path escapes dir %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("tar import failed: mkdir: %v", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("tar import failed: mkdir: %v", err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("tar import failed: create: %v", err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("tar import failed: copy: %v", err)
			}
			out.Close()
		case tar.TypeSymlink:
			//(header.Linkname is the link target; not path-escaped because it's interpreted by the guest kernel)
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("tar import failed: mkdir: %v", err)
			}
			if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("tar import failed: remove existing symlink: %v", err)
			}
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("tar import failed: symlink: %v", err)
			}
		case tar.TypeLink:
			// Hard link to a previously extracted entry. Resolve against the dest root.
			linkSrc := filepath.Join(dir, filepath.Clean(header.Linkname))
			if !strings.HasPrefix(linkSrc, filepath.Clean(dir)+string(filepath.Separator)) && linkSrc != filepath.Clean(dir) {
				return fmt.Errorf("tar import failed: hardlink target escapes dir %s", header.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("tar import failed: mkdir: %v", err)
			}
			if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("tar import failed: remove existing hardlink: %v", err)
			}
			if err := os.Link(linkSrc, target); err != nil {
				return fmt.Errorf("tar import failed: hardlink: %v", err)
			}
		case tar.TypeChar, tar.TypeBlock:
			// Device nodes require root + CAP_MKNOD; surface as an explicit error instead
			// of silently skipping, so a corrupted rootfs cannot go unnoticed.
			return fmt.Errorf("tar import failed: unsupported entry type %d at %q (device node); aborting", header.Typeflag, header.Name)
		default:
			return fmt.Errorf("tar import failed: unsupported entry type %d at %q; aborting", header.Typeflag, header.Name)
		}
	}
	importOk = true
	return nil
}
