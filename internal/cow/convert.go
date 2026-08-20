// convert.go exports image-format conversion between raw and qcow2 without a
// qemu-img subprocess — the pure-Go counterpart of:
//
//	qemu-img convert -O raw  <src> <dst>   # ConvertToRaw
//	qemu-img convert -O qcow2 <src> <dst>  # ConvertToQcow2
//
// ConvertToRaw flattens a (possibly layered) source into a standalone raw
// image; ConvertToQcow2 builds a standalone qcow2 (no backing file) from any
// source image, packing only the non-zero clusters. Both preserve the guest
// view byte-for-byte.
package cow

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ConvertToRaw flattens the image (and its backing chain) at srcPath into a
// standalone raw image at destPath. Sparse in, sparse out: regions that read
// as zero everywhere are skipped with seeks instead of written. It is the
// exported form of convertToRaw (qcow2.go), kept so the cow package has a
// symmetric Convert API alongside ConvertToQcow2; CommitOverlay aliases it
// for the overlay-merge use case.
func ConvertToRaw(ctx context.Context, srcPath, destPath string) error {
	return convertToRaw(ctx, srcPath, destPath)
}

// checkNotInChain rejects destPath when it is the same inode as srcPath or
// any member of img's backing chain. Creating the destination (O_TRUNC or a
// rename over it) would destroy the source's own backing data mid-read or
// leave a live overlay pointing at replaced content, so both convert paths
// must refuse BEFORE touching the filesystem.
func checkNotInChain(img guestImage, srcPath, destPath string) error {
	df, err := os.Stat(destPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing to clobber
		}
		return fmt.Errorf("cow: convert: stat dest: %w", err)
	}
	if sf, err := os.Stat(srcPath); err == nil && os.SameFile(sf, df) {
		return fmt.Errorf("cow: convert: source and destination are the same file: %s", destPath)
	}
	// Walk the opened chain: every live backing is a file the destination
	// must not replace. Compare inodes (os.SameFile), not strings — the
	// header may store relative or differently-spelled names.
	cur := img
	for cur != nil {
		q, ok := cur.(*qcow2Image)
		if !ok {
			break // raw images never have a backing
		}
		if q.backingAbs == "" {
			break
		}
		bf, err := os.Stat(q.backingAbs)
		if err == nil && os.SameFile(bf, df) {
			return fmt.Errorf("cow: convert: destination %s is a backing file of source %s (replacing it would corrupt the chain)", destPath, srcPath)
		}
		cur = q.backing
	}
	return nil
}

// ConvertToQcow2 builds a STANDALONE qcow2 image at destPath (no backing file)
// from any source image (raw or qcow2, possibly with its own backing chain).
// Only clusters that read as non-zero are written; fully-zero clusters are
// left unallocated (a standalone image reads them as zero anyway), so the
// output is dense and small — the pure-Go equivalent of
// `qemu-img convert -O qcow2`.
//
// opt.ClusterBits controls the dest cluster size (0 = package default 4 KiB);
// opt.PreallocMetadata is honored but defeats the point of conversion (the
// default OverlayOpt{ClusterBits: 4KiB, PreallocMetadata: false} produces the
// smallest image). Pass ConvertDefaultOpt for that default.
var ConvertDefaultOpt = OverlayOpt{ClusterBits: clusterBits, PreallocMetadata: false}

// ConvertToQcow2 converts srcPath into a standalone qcow2 at destPath. opt
// configures the destination cluster size and metadata preallocation; pass
// ConvertDefaultOpt (or OverlayOpt{ClusterBits: <bits>}) for sensible defaults.
func ConvertToQcow2(ctx context.Context, srcPath, destPath string, opt OverlayOpt) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePath(srcPath); err != nil {
		return err
	}
	if err := validatePath(destPath); err != nil {
		return err
	}
	absSrc, err := filepath.Abs(srcPath)
	if err != nil {
		return fmt.Errorf("cow: resolve src: %w", err)
	}
	absDst, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("cow: resolve dest: %w", err)
	}
	// Same-file guard: creating the dest with O_TRUNC would truncate the
	// source mid-read, destroying data before we ever finish converting. Use
	// os.SameFile (handles symlinks/hardlinks/relative-vs-absolute) and reject
	// without touching either file when src and dest resolve to the same inode.
	if sf, dErr := os.Stat(absSrc); dErr == nil {
		if df, dErr2 := os.Stat(absDst); dErr2 == nil {
			if os.SameFile(sf, df) {
				return fmt.Errorf("cow: convert: source and destination are the same file: %s", absDst)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(absDst), 0755); err != nil {
		return fmt.Errorf("cow: create dest dir: %w", err)
	}

	src, err := openGuestImage(absSrc)
	if err != nil {
		return fmt.Errorf("cow: convert: open src: %w", err)
	}
	defer src.Close()
	// Capture the source's permission bits from the ALREADY-OPEN descriptor
	// right here, before any copying: statting the PATH after the copy would
	// silently skip the chmod below whenever the path was replaced or
	// unlinked mid-convert (the open fd keeps the conversion alive), leaking
	// os.CreateTemp's 0600 through the final rename.
	srcMode := src.Mode()

	// Now that the chain is OPEN (and its backing inodes known), re-check
	// the destination against every member: converting onto the overlay's
	// own backing would let the final rename replace a file a live overlay
	// still references. The direct src/dst SameFile check above stays as a
	// fast path that fires before any directory is created.
	if err := checkNotInChain(src, absSrc, absDst); err != nil {
		return err
	}
	virtualSize := src.Size()
	if virtualSize == 0 {
		return fmt.Errorf("cow: convert: source %s has zero size", absSrc)
	}

	if opt.ClusterBits == 0 {
		opt.ClusterBits = clusterBits
	}
	// Build into a sibling temp file in the SAME directory as the dest so
	// the final rename is atomic on the same filesystem; a crash or failure
	// leaves the original dest (if any) untouched. createQcow2 opens with
	// O_TRUNC, so writing absDst directly would clobber it before we know the
	// conversion succeeded. os.CreateTemp gives a unique path per conversion
	// (concurrent converts to the same dest cannot stomp each other's temp)
	// and an exclusive create, so we never delete a pre-existing file that
	// might belong to someone else. We only need the reserved path, so close
	// the fd immediately; cleanup responsibility starts the moment the temp
	// file exists, so even a createQcow2 failure removes the partial file.
	tmpF, err := os.CreateTemp(filepath.Dir(absDst), ".convert-*.tmp")
	if err != nil {
		return fmt.Errorf("cow: convert: create temp in dest dir: %w", err)
	}
	tmp := tmpF.Name()
	if err := tmpF.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cow: convert: close temp placeholder: %w", err)
	}
	cleanupTmp := func() {
		// Best-effort: after a successful rename tmp no longer exists.
		_ = os.Remove(tmp)
	}
	// Standalone qcow2 (no backing). Preallocated metadata is pointless for a
	// conversion output and would bloat the dest; force it off unless the
	// caller is explicit — opt.PreallocMetadata true keeps what they asked.
	if err := createQcow2(tmp, virtualSize, "", "", opt); err != nil {
		cleanupTmp()
		return fmt.Errorf("cow: convert: create dest qcow2: %w", err)
	}

	w, err := OpenWritable(tmp)
	if err != nil {
		cleanupTmp()
		return fmt.Errorf("cow: convert: open dest: %w", err)
	}
	// closeAndCleanup closes w and removes tmp; called on every error return.
	// Rename happens only after an explicit successful close below, so we do
	// NOT defer w.Close() — that would close twice.
	closeAndCleanup := func() {
		w.Close()
		cleanupTmp()
	}

	// Stream the source through in cluster-sized chunks (aligned to the dest
	// cluster geometry so each write hits WriteAt's full-cluster fast path —
	// no CoW read-back). Whole-cluster zero regions are skipped so they stay
	// unallocated in the dest (reads as zero on a standalone image).
	bits := opt.ClusterBits
	cs := uint64(1) << bits
	// Round the transfer buffer up to a whole number of dest clusters and at
	// least 1 MiB for throughput; never larger than virtualSize.
	bufLen := uint64(1) << 20
	if r := bufLen % cs; r != 0 {
		bufLen += cs - r
	}
	if bufLen > virtualSize {
		bufLen = ((virtualSize + cs - 1) / cs) * cs
		if bufLen == 0 {
			bufLen = cs
		}
	}
	buf := make([]byte, bufLen)
	for off := uint64(0); off < virtualSize; off += bufLen {
		if err := ctx.Err(); err != nil {
			closeAndCleanup()
			return err
		}
		n := bufLen
		if rem := virtualSize - off; rem < n {
			n = rem
		}
		// Round n UP to a cluster so the last partial cluster still writes as a
		// full cluster (data beyond virtualSize is never read; padding with
		// zeros preserves the tail cluster's in-range bytes).
		if r := n % cs; r != 0 {
			pad := cs - r
			// Zero the padding region explicitly so stale buf bytes don't leak.
			clear(buf[n : n+pad])
			n += pad
		}
		chunk := buf[:n]
		m, err := src.ReadAt(chunk, int64(off))
		if err != nil && err != io.EOF {
			closeAndCleanup()
			return fmt.Errorf("cow: convert: read src at %#x: %w", off, err)
		}
		if uint64(m) < n {
			clear(chunk[m:])
		}
		// Write cluster-by-cluster, skipping all-zero clusters.
		for c := uint64(0); c < n; c += cs {
			if !allZero(chunk[c : c+cs]) {
				if _, err := w.WriteAt(chunk[c:c+cs], int64(off+c)); err != nil {
					closeAndCleanup()
					return fmt.Errorf("cow: convert: write dest at %#x: %w", off+c, err)
				}
			}
		}
	}
	// Sync, then close BEFORE renaming: an open writer would race the rename
	// and leave the replaced file with an unflushed buffer. A sync or close
	// failure aborts and cleans up tmp, leaving absDst untouched.
	if err := w.Sync(); err != nil {
		closeAndCleanup()
		return fmt.Errorf("cow: convert: sync dest: %w", err)
	}
	if err := w.Close(); err != nil {
		cleanupTmp()
		return fmt.Errorf("cow: convert: close dest: %w", err)
	}
	// Align the temp file's mode with the source before renaming: os.CreateTemp
	// creates it 0600 (umask cannot widen that), and createQcow2's O_CREATE
	// open of the already-existing temp file does not change the mode, so
	// without an explicit chmod the renamed result would keep 0600 no matter
	// what the source allowed. Mirror the permission bits captured from the
	// source descriptor at open time (srcMode) — a source under a private
	// (0600) task dir must stay 0600 — exactly the policy Compact applies.
	// Unconditional: the mode is known by construction, and a chmod failure is
	// fatal — do NOT rename a file with the wrong mode and pretend success.
	if err := os.Chmod(tmp, srcMode); err != nil {
		cleanupTmp()
		return fmt.Errorf("cow: convert: align dest mode: %w", err)
	}
	if err := os.Rename(tmp, absDst); err != nil {
		cleanupTmp()
		return fmt.Errorf("cow: convert: rename into place: %w", err)
	}
	return nil
}

// SniffFormat reports the on-disk format of path: "qcow2" if it begins with
// the qcow2 magic, "raw" otherwise. It is a convenience for callers that want
// to log/branch on an image's format without the full open path.
func SniffFormat(path string) string {
	if isQcow2(path) {
		return "qcow2"
	}
	return "raw"
}
