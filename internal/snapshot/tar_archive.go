package snapshot

import (
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"uml-container/internal/state"
	"uml-container/internal/tarutil"
)

var validContainerID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Export packages a container's state and data into a .tgz archive.
// The archive is written to a sibling temp file and atomically renamed onto
// destTgz only after tar succeeds, so a concurrent restore can never observe
// a half-written .tgz.
func Export(containerID string, destTgz string) error {
	if !validContainerID.MatchString(containerID) {
		return fmt.Errorf("invalid container ID")
	}
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(destTgz), ".snapshot-*.tgz.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp archive: %v", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	cmd := exec.Command("tar", "-czf", tmpName, "-C", dir, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return fmt.Errorf("tar export failed: %v, output: %s", err, string(out))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("failed to finalize archive: %v", err)
	}
	if err := os.Rename(tmpName, destTgz); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("failed to move archive into place: %v", err)
	}
	return nil
}

// Import restores a container from a .tgz archive.
//
// The target directory must not already exist: a repeated restore into the
// same id would otherwise overlay files onto a previous container's rootfs.
// We reserve the directory atomically via Mkdir (not MkdirAll) after a prior
// stat, so concurrent restore requests cannot race past the check.
func Import(srcTgz string, newContainerID string) error {
	if !validContainerID.MatchString(newContainerID) {
		return fmt.Errorf("invalid container ID")
	}

	dir, err := state.ContainerDir(newContainerID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("container directory already exists: %s", dir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat target directory: %v", err)
	}
	// Reserve atomically. If something created it between stat and Mkdir we
	// still fail loudly on the EEXIST instead of silently overlaying.
	if err := os.Mkdir(dir, 0755); err != nil {
		return fmt.Errorf("failed to reserve target directory: %v", err)
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

	// Extraction is delegated to the hardened tarutil extractor, which enforces
	// exactly the rules this function used to implement inline (path-traversal,
	// symlink-ancestor and device-node rejection) plus resource limits and
	// setuid/setgid/sticky stripping shared with image.Pull.
	if err := tarutil.Extract(gr, dir, tarutil.DefaultLimits()); err != nil {
		return fmt.Errorf("tar import failed: %v", err)
	}
	importOk = true
	return nil
}
