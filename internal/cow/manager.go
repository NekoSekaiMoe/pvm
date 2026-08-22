// Package cow implements block-level Copy-on-Write overlays using qcow2.
//
// Design (plan.md §5.2): N sandboxes share a single read-only base image
// (the immutable toolchain + repo snapshot). Each sandbox gets its own qcow2
// overlay backed by that base; all writes diverge into the overlay. The base
// never changes, so cache/share is safe across tenants.
//
// The OVERLAY is always qcow2. The BACKING image may be either raw or qcow2;
// CreateOverlay sniffs the magic and records the right backing format.
// This matches the two real callers: the vhost path serves the qcow2 overlay
// via qemu-storage-daemon over vhost-user-blk, while the ubd path mounts the
// base directly (no overlay). ubd cannot read qcow2, so a qcow2 base on the
// ubd path panics with "VFS: Unable to mount root fs" — callers that want
// ubd must hand CreateOverlay a raw base.
//
// qcow2 create/convert are implemented in pure Go (qcow2.go); no qemu-img
// binary is required at runtime.
//
// The previous host-side overlayfs-on-a-directory approach was broken: UML
// consumes a block device, so a directory rootfs could never be seen by the
// guest kernel. qcow2 fixes that at the storage layer.
package cow

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// qcow2Magic is the first 4 bytes of every qcow2 image ("QFI\xfb").
const qcow2Magic = "QFI\xfb"

// CreateOverlay creates a qcow2 overlay backed by baseImage. The base is
// treated as read-only; only overlayFile receives writes.
//
// The backing image may be raw or qcow2; CreateOverlay sniffs the backing
// magic (not the extension) and records the format in the overlay header, so
// consumers never probe untrusted backing content.
//
// The ctx bounds the (fast, metadata-only) creation; a nil ctx is treated as
// context.Background().
func CreateOverlay(ctx context.Context, baseImage, overlayFile string) error {
	return createOverlayValidated(ctx, baseImage, overlayFile, defaultOverlayOpt)
}

// CreateOverlayWithOptions is CreateOverlay with explicit qcow2 tuning
// (cluster size, metadata preallocation). See OverlayOpt.
//
// NOTE: unlike CreateOverlay (which applies defaultOverlayOpt — including
// PreallocMetadata: true), opt is used as given: fields left at their zero
// value are NOT defaulted. In particular OverlayOpt{} (or any opt without
// PreallocMetadata: true) creates an overlay with NO preallocated L2 tables
// or refcount blocks — first writes then pay the lazy metadata allocations
// that preallocation exists to avoid.
func CreateOverlayWithOptions(ctx context.Context, baseImage, overlayFile string, opt OverlayOpt) error {
	if opt.ClusterBits == 0 {
		opt.ClusterBits = clusterBits
	}
	return createOverlayValidated(ctx, baseImage, overlayFile, opt)
}

// createOverlayValidated validates paths, removes stale overlays, sniffs the
// backing format and writes the overlay with opt.
func createOverlayValidated(ctx context.Context, baseImage, overlayFile string, opt OverlayOpt) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if baseImage == "" || overlayFile == "" {
		return errors.New("cow: base and overlay paths required")
	}
	// Validate BOTH paths before touching the filesystem. validatePath is the
	// guard against option/protocol injection patterns (commas, leading '-',
	// remote-image specifiers like json:/nbd://) that qcow2-capable consumers
	// might otherwise interpret.
	if err := validatePath(baseImage); err != nil {
		return err
	}
	if err := validatePath(overlayFile); err != nil {
		return err
	}
	// Resolve both paths to ABSOLUTE before recording the backing reference.
	// qcow2 consumers resolve a relative backing name against the OVERLAY's
	// directory, not the caller's CWD — storing an absolute path makes the
	// reference unambiguous regardless of who opens the overlay from where.
	absBase, err := filepath.Abs(baseImage)
	if err != nil {
		return fmt.Errorf("cow: resolve backing path: %w", err)
	}
	absOverlay, err := filepath.Abs(overlayFile)
	if err != nil {
		return fmt.Errorf("cow: resolve overlay path: %w", err)
	}
	baseImage, overlayFile = absBase, absOverlay
	if _, err := os.Stat(baseImage); err != nil {
		return fmt.Errorf("cow: backing image not found: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(overlayFile), 0755); err != nil {
		return fmt.Errorf("cow: create overlay dir: %w", err)
	}

	// Remove a stale overlay so re-creating after a crash is idempotent. We do
	// NOT silently reuse: a leftover overlay might contain partial writes from
	// a previous, failed task. Explicit recreation = known-good empty state.
	if _, err := os.Stat(overlayFile); err == nil {
		if err := os.Remove(overlayFile); err != nil {
			return fmt.Errorf("cow: remove stale overlay: %w", err)
		}
	}

	// Sniff the backing format by magic and derive the virtual size from the
	// base: header field for qcow2, file size for raw.
	backing, err := openGuestImage(baseImage)
	if err != nil {
		return fmt.Errorf("cow: open backing image: %w", err)
	}
	virtualSize := backing.Size()
	backing.Close()
	// Record the base image's directory as an allowed backing root so this
	// overlay (and any descendant) can resolve its backing on later opens.
	RegisterBackingRoot(filepath.Dir(absBase))
	return createQcow2(overlayFile, virtualSize, baseImage, backing.Format(), opt)
}

// isQcow2 reports whether path begins with the qcow2 magic ("QFI\xfb"). A
// missing or unreadable file is treated as "not qcow2" so the caller surfaces
// a clear "convert it first" error instead of a confusing qemu-img failure.
func isQcow2(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := f.Read(hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == qcow2Magic
}

// CommitOverlay merges an overlay back into a new full raw image (leaving
// the original base untouched). Used when a task's output should be captured
// as a standalone artifact (plan.md §5.3 Artifact = declared output only).
func CommitOverlay(ctx context.Context, overlayFile, destImage string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validatePath(overlayFile); err != nil {
		return err
	}
	if err := validatePath(destImage); err != nil {
		return err
	}
	// Absolutize for consistency with CreateOverlay: relative paths would
	// resolve against the (possibly changed) caller CWD at MkdirAll time.
	if abs, err := filepath.Abs(overlayFile); err == nil {
		overlayFile = abs
	}
	if abs, err := filepath.Abs(destImage); err == nil {
		destImage = abs
	}
	if err := os.MkdirAll(filepath.Dir(destImage), 0755); err != nil {
		return err
	}
	return convertToRaw(ctx, overlayFile, destImage)
}

// backingRoots are the directory trees inside which a qcow2 header's backing
// reference must resolve. Defaults cover every storage root PVM derives:
// engine root (PVM_COW_ROOT or /var/lib/uml-container/cow), the image store
// (/var/lib/uml-container/images) and the container state root (PVM_STATE_ROOT
// or /var/lib/uml-container/containers). CreateOverlay additionally registers
// the directory of every base image it is handed, so overlays backed by user-
// supplied base paths keep resolving.
var (
	backingRootsMu      sync.Mutex
	dynamicBackingRoots = map[string]bool{}
)

// staticBackingRoots returns the environment-derived backing roots at CALL
// time (not package init): tests flip PVM_COW_ROOT/PVM_STATE_ROOT via t.Setenv
// after init has already run, and a daemon re-reading its config must not be
// pinned to the values seen at process start. Defaults cover every storage
// root PVM derives: engine root (PVM_COW_ROOT or
// /var/lib/uml-container/cow), the image store
// (/var/lib/uml-container/images) and the container state root
// (PVM_STATE_ROOT or /var/lib/uml-container/containers).
func staticBackingRoots() []string {
	cowRoot := os.Getenv("PVM_COW_ROOT")
	if cowRoot == "" {
		cowRoot = "/var/lib/uml-container/cow"
	}
	stateRoot := os.Getenv("PVM_STATE_ROOT")
	if stateRoot == "" {
		stateRoot = "/var/lib/uml-container/containers"
	}
	return []string{cowRoot, "/var/lib/uml-container/images", stateRoot}
}

// RegisterBackingRoot whitelists dir as a permitted backing location for
// qcow2 images opened later. CreateOverlay calls it with the resolved base
// image's directory; tests can use it for temp dirs.
func RegisterBackingRoot(dir string) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return
	}
	backingRootsMu.Lock()
	dynamicBackingRoots[abs] = true
	backingRootsMu.Unlock()
}

// validateBackingName syntactically validates the raw backing name stored in
// a qcow2 header before anything resolves or opens it: no commas/NULs, no
// leading '-' (option injection), no remote/protocol specifiers — the same
// rules validatePath applies to caller-provided paths.
func validateBackingName(name string) error {
	if name == "" {
		return errors.New("cow: empty backing name")
	}
	return validatePath(name)
}

// backingPathAllowed enforces containment of a backing path: it must live
// under one of the managed roots, under the image's own directory tree, or
// under a dynamically registered root. Relative names that climb out of the
// image's directory with ".." therefore fail unless they land back in a
// managed root, and absolute names pointing at arbitrary system files are
// rejected outright. Both the candidate path and every allowed root are
// SYMLINK-RESOLVED before the containment comparison, and the resolved
// candidate is returned so the caller opens exactly what was validated —
// a lexical path that sneaks past via a symlink plant is otherwise
// indistinguishable from a legitimate one.
func backingPathAllowed(imagePath, candidate string) (string, error) {
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		// Unresolvable backing (missing file, unreadable ancestor): reject
		// rather than fall back to the lexical path — that fallback is the
		// symlink-planting escape hatch.
		return "", fmt.Errorf("cow: resolve backing %s: %w", candidate, err)
	}
	absImageDir, err := filepath.Abs(filepath.Dir(imagePath))
	if err != nil {
		return "", fmt.Errorf("cow: resolve image dir of %s: %w", imagePath, err)
	}
	candidates := []string{absImageDir}
	backingRootsMu.Lock()
	candidates = append(candidates, staticBackingRoots()...)
	for r := range dynamicBackingRoots {
		candidates = append(candidates, r)
	}
	backingRootsMu.Unlock()
	for _, root := range candidates {
		realRoot, rerr := filepath.EvalSymlinks(root)
		if rerr != nil {
			// A root that cannot be resolved (missing/unreadable) simply
			// cannot vouch for anything; other roots still apply.
			continue
		}
		if withinSubtree(real, realRoot) {
			return real, nil
		}
	}
	return "", fmt.Errorf("cow: backing file %s (of %s) is outside all managed storage roots", real, imagePath)
}

// withinSubtree reports whether p equals or lives below dir (both absolute,
// lexically cleaned).
func withinSubtree(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && rel != "")
}

// validatePath rejects empty, comma-bearing, NUL-bearing and option/protocol
// injection patterns. Commas delimit image-option syntax for qcow2-aware
// consumers; a leading '-' would let a filename pose as a flag; and remote
// prefixes (json:, nbd://, ...) name remote/synthetic image sources rather
// than local files — we refuse any of those so an untrusted path can never
// be parsed as a remote backing image.
func validatePath(p string) error {
	if p == "" {
		return errors.New("cow: empty path")
	}
	if strings.ContainsAny(p, ",\x00") {
		return fmt.Errorf("cow: path %q contains forbidden sequence (comma or NUL)", p)
	}
	// A leading '-' turns a filename into a flag for many tools; reject it.
	// Absolute/relative paths like "./foo" are allowed as long as the first
	// path element doesn't start with '-'.
	first := p
	if idx := strings.IndexByte(p, '/'); idx >= 0 {
		first = p[:idx]
	}
	if strings.HasPrefix(first, "-") {
		return fmt.Errorf("cow: path %q starts with '-' (option injection)", p)
	}
	// qemu-img accepts protocol/specifier prefixes (json:, nbd+tcp://, http://,
	// ssh://, ...) that point at remote or synthetic image sources. They are
	// recognized case-insensitively and may carry a scheme before any '/'.
	for _, pref := range []string{"json:", "nbd", "http://", "https://", "ftp://", "ssh://", "gluster://", "iscsi://"} {
		if strings.HasPrefix(strings.ToLower(p), pref) {
			return fmt.Errorf("cow: path %q looks like a qemu-img image specifier (remote/protocol prefix forbidden)", p)
		}
	}
	return nil
}
