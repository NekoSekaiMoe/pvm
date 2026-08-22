package cow

import "errors"

// Sentinel errors classifying engine failures. Every operation wraps the
// matching sentinel with %w while keeping its human-readable context, so
// callers — the REST layer in particular — classify outcomes with
// errors.Is instead of matching message substrings (which breaks the
// moment a wrapped lower-level error happens to contain the same words).
//
// The sentinel text is chosen so wrapped messages read exactly like the
// historical free-form errors; only the %w plumbing is new.
var (
	// ErrInvalid marks rejected names/sizes (bad characters, the reserved
	// "snap-" prefix, zero size). Maps to HTTP 400.
	ErrInvalid = errors.New("invalid")
	// ErrNotFound marks a missing volume or snapshot. Maps to HTTP 404.
	ErrNotFound = errors.New("not found")
	// ErrExists marks a colliding volume/snapshot name. Maps to HTTP 409.
	ErrExists = errors.New("already exists")
	// ErrReferenced marks a delete vetoed by live dependents (another
	// volume/snapshot branches from the target). Maps to HTTP 409.
	ErrReferenced = errors.New("referenced by")
	// ErrBackedBy marks a rollback vetoed by live dependents: replacing the
	// volume in place would silently change what dependents observe.
	// Maps to HTTP 409.
	ErrBackedBy = errors.New("is backed by it")
	// ErrRefScan marks a failed dependency scan. Guarding operations fail
	// CLOSED on it: without a successful scan they cannot know whether
	// dependents exist. Maps to HTTP 409.
	ErrRefScan = errors.New("scan references")
)
