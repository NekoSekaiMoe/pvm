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
	if err := os.MkdirAll(filepath.Dir(absDst), 0755); err != nil {
		return fmt.Errorf("cow: create dest dir: %w", err)
	}

	src, err := openGuestImage(absSrc)
	if err != nil {
		return fmt.Errorf("cow: convert: open src: %w", err)
	}
	defer src.Close()
	virtualSize := src.Size()
	if virtualSize == 0 {
		return fmt.Errorf("cow: convert: source %s has zero size", absSrc)
	}

	if opt.ClusterBits == 0 {
		opt.ClusterBits = clusterBits
	}
	// Standalone qcow2 (no backing). Preallocated metadata is pointless for a
	// conversion output and would bloat the dest; force it off unless the
	// caller is explicit — opt.PreallocMetadata true keeps what they asked.
	if err := createQcow2(absDst, virtualSize, "", "", opt); err != nil {
		return fmt.Errorf("cow: convert: create dest qcow2: %w", err)
	}

	w, err := OpenWritable(absDst)
	if err != nil {
		return fmt.Errorf("cow: convert: open dest: %w", err)
	}
	defer w.Close()

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
			return fmt.Errorf("cow: convert: read src at %#x: %w", off, err)
		}
		if uint64(m) < n {
			clear(chunk[m:])
		}
		// Write cluster-by-cluster, skipping all-zero clusters.
		for c := uint64(0); c < n; c += cs {
			if !allZero(chunk[c : c+cs]) {
				if _, err := w.WriteAt(chunk[c:c+cs], int64(off+c)); err != nil {
					return fmt.Errorf("cow: convert: write dest at %#x: %w", off+c, err)
				}
			}
		}
	}
	if err := w.Sync(); err != nil {
		return fmt.Errorf("cow: convert: sync dest: %w", err)
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
