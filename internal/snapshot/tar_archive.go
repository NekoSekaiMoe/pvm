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
	dir := state.ContainerDir(containerID)
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

	dir := state.ContainerDir(newContainerID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

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
		case tar.TypeReg:
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
		}
	}
	return nil
}
