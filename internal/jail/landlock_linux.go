//go:build linux

package jail

import (
	"fmt"
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

// landlockRuleAccess returns the access mask legal for a rule tied to a path
// of the given mode. The kernel (landlock_append_fs_rule) hard-fails EINVAL
// when a NON-directory rule carries directory-only rights (READ_DIR,
// MAKE_*, REMOVE_*, ...): a file rule may only hold
// EXECUTE|WRITE_FILE|READ_FILE|TRUNCATE|IOCTL_DEV. This is what killed the
// jail helper with "add rule for /images/rootfs.img: invalid argument" once
// the rootfs image started being allowlisted as a file (CI run 88459717851).
func landlockRuleAccess(mode uint32) uint64 {
	if mode&unix.S_IFMT == unix.S_IFDIR {
		return landlockAccessFSRw
	}
	// EXECUTE | WRITE_FILE | READ_FILE — the subset of landlockAccessFSRw
	// that is valid on non-directories (TRUNCATE/IOCTL_DEV are not part of
	// the handled set, so they cannot be granted either).
	return 0x01 | 0x02 | 0x04
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
		// O_PATH is required for two reasons: it is the fd type
		// LANDLOCK_ADD_RULE expects for parent_fd, and it opens EVERY file
		// type — a plain os.Open(O_RDONLY) fails ENXIO on unix sockets
		// (vhost-user socket bind) and is wrong for device nodes
		// (/dev/net/tun bind).
		fd, openErr := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return fmt.Errorf("landlock: open allowed path %s: %w", p, openErr)
		}
		var st unix.Stat_t
		if statErr := unix.Fstat(fd, &st); statErr != nil {
			unix.Close(fd)
			return fmt.Errorf("landlock: stat allowed path %s: %w", p, statErr)
		}
		pathAttr := landlockPathBeneathAttr{
			allowedAccess: landlockRuleAccess(st.Mode),
			parentFd:      int32(fd),
		}
		_, _, addErr := unix.Syscall6(
			unix.SYS_LANDLOCK_ADD_RULE,
			uintptr(rulesetFd),
			uintptr(landlockRulePathBeneath),
			uintptr(unsafe.Pointer(&pathAttr)),
			0, 0, 0,
		)
		unix.Close(fd)
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
