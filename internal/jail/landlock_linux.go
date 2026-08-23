//go:build linux

package jail

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock access flags
const (
	landlockAccessFSRw = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000
)

type landlockRulesetAttr struct {
	handledAccessFS uint64
}

type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
}

// ApplyLandlockLockdown restricts the calling process so it can only access the given paths.
func ApplyLandlockLockdown(allowedPaths []string) error {
	if len(allowedPaths) == 0 {
		return nil
	}

	// 1. Create Ruleset
	attr := landlockRulesetAttr{
		handledAccessFS: landlockAccessFSRw,
	}

	fd, _, err := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if err != 0 {
		if err == unix.ENOSYS || err == unix.EOPNOTSUPP {
			return nil // Landlock not supported on this kernel; non-fatal here (checked by CheckSecurity)
		}
		return fmt.Errorf("landlock: create ruleset: %w", err)
	}
	rulesetFd := int(fd)
	defer unix.Close(rulesetFd)

	// 2. Add path beneath rules
	const landlockRulePathBeneath = 1

	for _, p := range allowedPaths {
		f, openErr := os.Open(p)
		if openErr != nil {
			return fmt.Errorf("landlock: open allowed path %s: %w", p, openErr)
		}
		pathAttr := landlockPathBeneathAttr{
			allowedAccess: landlockAccessFSRw,
			parentFd:      int32(f.Fd()),
		}
		_, _, addErr := unix.Syscall6(
			unix.SYS_LANDLOCK_ADD_RULE,
			uintptr(rulesetFd),
			uintptr(landlockRulePathBeneath),
			uintptr(unsafe.Pointer(&pathAttr)),
			0, 0, 0,
		)
		f.Close()
		if addErr != 0 && addErr != unix.ENOSYS {
			return fmt.Errorf("landlock: add rule for %s: %w", p, addErr)
		}
	}

	// 3. Enforce self restriction
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("landlock: set no_new_privs: %w", err)
	}

	_, _, resErr := unix.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFd),
		0,
		0,
	)
	if resErr != 0 && resErr != unix.ENOSYS {
		return fmt.Errorf("landlock: restrict self: %w", resErr)
	}

	return nil
}
