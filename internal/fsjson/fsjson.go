// Package fsjson provides crash-safe atomic JSON file persistence.
//
// Write serializes a value to a temporary file in the target directory,
// fsyncs and closes it (propagating errors), and finally renames it over
// the destination. Readers therefore never observe a partial file, and a
// crash mid-write leaves the previous contents intact.
package fsjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrDurability reports that the rename was committed (the new content IS
// the on-disk state) but the follow-up directory fsync could not be
// confirmed. Unlike ordinary write errors, callers receiving an error that
// wraps ErrDurability should re-read the target before concluding failure.
var ErrDurability = errors.New("fsjson: rename committed but durability confirmation failed")

// Write atomically persists v as pretty-printed JSON at path. The temporary
// file is synced and closed before the rename; on any failure the temporary
// file is removed and path is left untouched.
func Write(path string, v any) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("fsjson: sync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("fsjson: close %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("fsjson: rename %s -> %s: %w", name, path, err)
	}
	// fsync the parent directory so the rename itself (a directory entry
	// update) survives a crash; syncing only the file would leave the new
	// name uncommitted on some filesystems (e.g. ext4 with delayed allocation).
	// Failures here are distinct: the write is committed, only the durability
	// confirmation is missing.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("%w: open %s: %w", ErrDurability, dir, err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("%w: sync %s: %w", ErrDurability, dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("%w: close %s: %w", ErrDurability, dir, err)
	}
	return nil
}
