package volume

// hostmount.go — explicit host-directory mounts behind a deployment-wide
// prefix whitelist.
//
// Ordinary volumes are plugin-backed and always land under VolumeBaseDir
// (validateHostPath containment). An explicit host mount instead binds a
// pre-existing host directory into the guest read-only or read-write —
// the operator-facing "share this dataset with the sandbox" escape hatch.
//
// Because that punches a hole in the VolumeBaseDir boundary, it is gated
// on PVM_HOST_MOUNT_PREFIXES (comma-separated absolute path prefixes,
// e.g. "/srv/shared,/data/datasets"): an explicit HostPath is rejected
// unless the deployment configured at least one prefix AND the resolved
// path stays under one. Symlinks are resolved before matching, so a link
// pointing outside the whitelist cannot smuggle a path in. Empty
// whitelist = explicit host mounts disabled entirely (default).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnvHostMountPrefixes is the deployment-wide whitelist variable.
const EnvHostMountPrefixes = "PVM_HOST_MOUNT_PREFIXES"

// ParseHostMountPrefixes parses the env value: comma (or newline)
// separated absolute prefixes; "#" comments and empty entries dropped.
// Every entry must be absolute and cleaned; a relative entry is an error
// (silently dropping it would widen the whitelist's meaning).
func ParseHostMountPrefixes(value string) ([]string, error) {
	var out []string
	for _, raw := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' }) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if !filepath.IsAbs(raw) {
			return nil, fmt.Errorf("volume: host-mount prefix %q must be absolute", raw)
		}
		out = append(out, filepath.Clean(raw))
	}
	return out, nil
}

// HostMountPrefixesFromEnv loads and validates the whitelist; an invalid
// entry is an error the caller must surface (start fails closed).
func HostMountPrefixesFromEnv() ([]string, error) {
	return ParseHostMountPrefixes(os.Getenv(EnvHostMountPrefixes))
}

// pathUnderPrefix reports whether resolved (already symlink-resolved,
// absolute) is prefix or equal to one of prefixes.
func pathUnderPrefix(resolved string, prefixes []string) bool {
	for _, p := range prefixes {
		if resolved == p || strings.HasPrefix(resolved, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// resolvePrefixes best-effort-resolves each whitelist prefix: a prefix
// that itself goes through a symlink ("/data -> /srv/data") would never
// match a fully-resolved mount path otherwise. Unresolvable prefixes
// (not on disk yet, raced deletion) stay lexical — they can only match
// paths whose ancestors resolve identically, never widen the whitelist.
func resolvePrefixes(prefixes []string) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if resolved, err := resolveExisting(p); err == nil {
			out = append(out, resolved)
		} else {
			out = append(out, p)
		}
	}
	return out
}

// validateExplicitHostPath checks an operator-supplied HostPath and
// RETURNS the symlink-resolved absolute path the caller must mount. The
// directory must exist, resolve under a configured prefix, and the
// whitelist must be non-empty. root-bypass ("/") is refused outright —
// a root prefix would make the whitelist decorative. Mounting the
// RETURNED path (not the operator's original spelling) closes the
// validate-then-mount TOCTOU: a symlink swapped after this check cannot
// redirect the bind mount.
func validateExplicitHostPath(hostPath string, prefixes []string) (string, error) {
	if len(prefixes) == 0 {
		return "", fmt.Errorf("volume: explicit host mount %q refused: %s is not configured (host mounts are disabled)", hostPath, EnvHostMountPrefixes)
	}
	if !filepath.IsAbs(hostPath) {
		return "", fmt.Errorf("volume: explicit host mount %q must be absolute", hostPath)
	}
	clean := filepath.Clean(hostPath)
	for _, p := range prefixes {
		if p == string(filepath.Separator) {
			return "", fmt.Errorf("volume: host-mount whitelist contains \"/\" — refusing to allow root")
		}
	}
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("volume: explicit host mount %q not accessible: %w", hostPath, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("volume: explicit host mount %q is not a directory", hostPath)
	}
	resolved, err := resolveExisting(clean)
	if err != nil {
		return "", fmt.Errorf("volume: explicit host mount %q not resolvable: %w", hostPath, err)
	}
	if !pathUnderPrefix(resolved, resolvePrefixes(prefixes)) {
		return "", fmt.Errorf("volume: explicit host mount %q outside the %s whitelist", hostPath, EnvHostMountPrefixes)
	}
	return resolved, nil
}
