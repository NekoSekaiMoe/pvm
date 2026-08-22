// Package tarutil provides a hardened tar extractor for untrusted archives
// (registry image layers, snapshot imports). Unlike `tar -xf`, extraction is
// fully controlled by this process:
//
//   - path traversal members ("..", absolute paths) are rejected;
//   - symlinks may only point at relative targets that resolve INSIDE the
//     destination; hardlink targets must also stay inside;
//   - no path component may traverse an existing symlink (pivot attack);
//   - device nodes, FIFOs and other special types are rejected outright;
//   - setuid/setgid/sticky bits are stripped from every extracted entry, so a
//     root-owned extraction can never plant privileged executables;
//   - resource limits (per-file bytes, total bytes, entry count) bound the
//     damage of a zip-bomb-style archive and are configurable.
package tarutil

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// Limits bounds the resources one extraction may consume. The zero value is
// invalid; use DefaultLimits (or explicitly set fields) — Extract rejects a
// zero Limits so callers cannot silently run unbounded.
type Limits struct {
	// MaxFileSize caps the uncompressed size of a single regular file.
	MaxFileSize int64
	// MaxTotalBytes caps the cumulative uncompressed size of all entries.
	MaxTotalBytes int64
	// MaxEntries caps the number of archive members processed.
	MaxEntries int64
}

// DefaultLimits returns the production limits: 1 GiB per file, 8 GiB total,
// 200k entries — generous for container rootfs layers, far below anything
// that could exhaust disk or memory through a single Pull/Import call.
func DefaultLimits() Limits {
	return Limits{
		MaxFileSize:   1 << 30,
		MaxTotalBytes: 8 << 30,
		MaxEntries:    200_000,
	}
}

func (l Limits) validate() error {
	if l.MaxFileSize <= 0 || l.MaxTotalBytes <= 0 || l.MaxEntries <= 0 {
		return fmt.Errorf("tarutil: invalid limits (file=%d total=%d entries=%d): must all be > 0", l.MaxFileSize, l.MaxTotalBytes, l.MaxEntries)
	}
	if l.MaxFileSize > l.MaxTotalBytes {
		return fmt.Errorf("tarutil: invalid limits: MaxFileSize %d exceeds MaxTotalBytes %d", l.MaxFileSize, l.MaxTotalBytes)
	}
	return nil
}

// Extract unpacks the tar stream r into dest (which must already exist),
// enforcing the safety rules of this package with the given limits.
func Extract(r io.Reader, dest string, limits Limits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("tarutil: resolve dest: %w", err)
	}
	tr := tar.NewReader(r)
	var total int64
	var entries int64
	// Intended directory modes, applied at the END of a successful extraction
	// (see applyDirModes). Keyed by absolute path; later entries win, matching
	// tar's last-writer-wins semantics.
	dirModes := make(map[string]os.FileMode)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// Success: now that every member is extracted, restore the intended
			// directory modes. A restrictive parent (e.g. 0555) must not bite
			// before its children exist.
			return applyDirModes(dirModes)
		}
		if err != nil {
			return fmt.Errorf("tarutil: read tar: %w", err)
		}
		// PAX global extended headers ('g') are archive-wide metadata, not
		// members: tar.Reader surfaces them as pseudo-entries. Skip them
		// without counting against MaxEntries — they carry no extraction cost.
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		entries++
		if entries > limits.MaxEntries {
			return fmt.Errorf("tarutil: archive exceeds %d entries; aborting", limits.MaxEntries)
		}
		name, err := safeName(hdr.Name)
		if err != nil {
			return err
		}
		target := filepath.Join(absDest, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := checkNoSymlinkAncestor(absDest, target); err != nil {
				return err
			}
			perm := os.FileMode(hdr.Mode).Perm() & 0777 //nolint:gosec // masked to permission bits (strips setuid/setgid/sticky)
			// Record the intended mode even for pre-existing directories
			// (last entry for a path wins). Create with owner-write added so
			// nested members can still be created under it; the recorded mode
			// is restored by applyDirModes after extraction completes.
			dirModes[target] = perm
			if err := os.MkdirAll(target, perm|0700); err != nil {
				return fmt.Errorf("tarutil: mkdir %s: %w", name, err)
			}
		case tar.TypeReg:
			if hdr.Size > limits.MaxFileSize {
				return fmt.Errorf("tarutil: entry %q (%d bytes) exceeds per-file limit %d", name, hdr.Size, limits.MaxFileSize)
			}
			total += hdr.Size
			if total > limits.MaxTotalBytes {
				return fmt.Errorf("tarutil: archive exceeds total size limit %d; aborting", limits.MaxTotalBytes)
			}
			if err := extractFile(tr, absDest, target, name, hdr.Mode, hdr.Size); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := extractSymlink(hdr, absDest, target); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := extractHardlink(hdr, absDest, target); err != nil {
				return err
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return fmt.Errorf("tarutil: unsupported entry type %d at %q (device node/fifo); aborting", hdr.Typeflag, hdr.Name)
		default:
			return fmt.Errorf("tarutil: unsupported entry type %d at %q; aborting", hdr.Typeflag, hdr.Name)
		}
	}
}

// applyDirModes restores the intended permission bits for extracted
// directories, deepest path first. Ordering matters: a parent intended to
// lose execute (e.g. 0666) would block chmod on its own children, so children
// are finalized before their ancestors.
func applyDirModes(dirModes map[string]os.FileMode) error {
	paths := make([]string, 0, len(dirModes))
	for p := range dirModes {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, p := range paths {
		if err := os.Chmod(p, dirModes[p]); err != nil {
			return fmt.Errorf("tarutil: chmod dir %s to %v: %w", p, dirModes[p], err)
		}
	}
	return nil
}

// safeName validates an archive member name and returns it cleaned relative
// to the destination root: absolute paths and any traversal via ".." are
// rejected rather than rewritten (fail closed on malicious names).
func safeName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("tarutil: empty member name")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("tarutil: absolute member path %q rejected", name)
	}
	clean := filepath.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("tarutil: member %q escapes the destination (..)", name)
	}
	if strings.ContainsRune(clean, 0) {
		return "", fmt.Errorf("tarutil: member %q contains NUL", name)
	}
	return clean, nil
}

// extractFile creates target and copies exactly hdr.Size bytes from tr into
// it, enforcing the per-file limit. Mode keeps only permission bits:
// setuid/setgid/sticky are stripped so an extraction running as root cannot
// be tricked into producing privileged binaries.
func extractFile(tr io.Reader, absDest, target, name string, mode int64, size int64) error {
	if err := checkNoSymlinkAncestor(absDest, filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("tarutil: mkdir parent of %s: %w", name, err)
	}
	// An existing SYMLINK at target must not be followed by O_TRUNC below.
	// Replace it like GNU tar does (last writer wins).
	if fi, err := os.Lstat(target); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(target); err != nil {
			return fmt.Errorf("tarutil: remove stale symlink at %s: %w", name, err)
		}
	}
	perm := os.FileMode(mode).Perm() & 0777 //nolint:gosec // header value masked to permission bits
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return fmt.Errorf("tarutil: create %s: %w", name, err)
	}
	n, copyErr := io.Copy(out, io.LimitReader(tr, size)) //nolint:gosec // size bounded by MaxFileSize above
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return fmt.Errorf("tarutil: write %s: %w", name, copyErr)
	}
	if n != size {
		return fmt.Errorf("tarutil: entry %q truncated: got %d of %d bytes", name, n, size)
	}
	// Explicit chmod: OpenFile applies perm only at create time, so an
	// EXISTING file keeps its old mode (and would need the new one), and a
	// new file's mode is masked by the process umask. Applying the archive's
	// permission bits directly makes both deterministic.
	if err := os.Chmod(target, perm); err != nil {
		return fmt.Errorf("tarutil: chmod %s to %v: %w", name, perm, err)
	}
	return nil
}

// extractSymlink creates a symlink whose target must be RELATIVE and resolve
// inside dest. Absolute symlink targets are refused outright: they trivially
// point outside the extraction root.
func extractSymlink(hdr *tar.Header, absDest, target string) error {
	link := hdr.Linkname
	if strings.HasPrefix(link, "/") {
		return fmt.Errorf("tarutil: absolute symlink %q -> %q escapes the destination", hdr.Name, link)
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(target), link))
	if resolved != absDest && !strings.HasPrefix(resolved, absDest+string(filepath.Separator)) {
		return fmt.Errorf("tarutil: symlink %q -> %q escapes the destination", hdr.Name, link)
	}
	if err := checkNoSymlinkAncestor(absDest, filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("tarutil: mkdir parent of %s: %w", hdr.Name, err)
	}
	// Replace any existing entry (last-writer-wins, like GNU tar -xf).
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("tarutil: remove existing %s: %w", hdr.Name, err)
	}
	if err := os.Symlink(link, target); err != nil {
		return fmt.Errorf("tarutil: symlink %s: %w", hdr.Name, err)
	}
	return nil
}

// extractHardlink links target to an earlier member inside dest.
func extractHardlink(hdr *tar.Header, absDest, target string) error {
	src := filepath.Clean(filepath.Join(absDest, hdr.Linkname))
	if !strings.HasPrefix(src, absDest+string(filepath.Separator)) && src != absDest {
		return fmt.Errorf("tarutil: hardlink target %q escapes the destination", hdr.Linkname)
	}
	// The SOURCE path is resolved by the kernel during link(2): a symlinked
	// ancestor on it ("dir -> /etc" planted earlier, then a hardlink to
	// "dir/passwd") would link a file OUTSIDE dest even though the member
	// name itself stays inside. link(2) does not dereference the FINAL
	// component of its oldname, so a hardlink whose source name itself is a
	// symlink (linking over a symlink target name) stays a legitimate,
	// in-dest operation — guard only the intermediate components of src.
	if err := checkNoSymlinkAncestor(absDest, filepath.Dir(src)); err != nil {
		return err
	}
	if err := checkNoSymlinkAncestor(absDest, filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("tarutil: mkdir parent of %s: %w", hdr.Name, err)
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("tarutil: remove existing %s: %w", hdr.Name, err)
	}
	srcFi, serr := os.Lstat(src)
	if serr != nil {
		return fmt.Errorf("tarutil: stat hardlink source %s: %w", hdr.Linkname, serr)
	}
	if srcFi.Mode()&os.ModeSymlink != 0 {
		if symlinkTarget, err := os.Readlink(src); err == nil {
			_ = os.Remove(target)
			if err2 := os.Symlink(symlinkTarget, target); err2 == nil {
				return nil
			}
		}
	}
	if err := unix.Linkat(unix.AT_FDCWD, src, unix.AT_FDCWD, target, 0); err != nil {
		return fmt.Errorf("tarutil: hardlink %s -> %s: %w", hdr.Name, hdr.Linkname, err)
	}
	return nil
}

// checkNoSymlinkAncestor walks each path component of target below root and
// fails if any existing component is a symlink. This closes the pivot attack
// where an earlier archive member plants "a -> /etc" and a later member then
// writes through "a/passwd".
func checkNoSymlinkAncestor(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return fmt.Errorf("tarutil: resolve path below dest: %w", err)
	}
	curr := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			continue
		}
		curr = filepath.Join(curr, part)
		fi, err := os.Lstat(curr)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // nothing left to check below the first missing dir
			}
			return fmt.Errorf("tarutil: stat %s: %w", curr, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("tarutil: path %q traverses symlink %s", target, curr)
		}
	}
	return nil
}
