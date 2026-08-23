//go:build linux

package jail

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sysLandlockCreateRuleset is the syscall number for landlock_create_ruleset
const (
	sysLandlockCreateRuleset = 444 // on x86_64 and arm64 Linux
)

func probeHostCapabilities() HostCapabilities {
	caps := HostCapabilities{
		HasSeccomp:  true, // Linux kernels >= 3.5 support seccomp-bpf
		HasMountNS:  true,
		HasUserNS:   true,
		HasLandlock: false,
	}

	// 1. Probe Seccomp / PR_SET_NO_NEW_PRIVS
	if err := unix.Prctl(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil && err != unix.EINVAL {
		caps.HasSeccomp = false
	}

	// 2. Probe Mount Namespace
	if _, err := os.Stat("/proc/self/ns/mnt"); err != nil {
		caps.HasMountNS = false
	}

	// 3. Probe User Namespace
	if _, err := os.Stat("/proc/self/ns/user"); err != nil {
		caps.HasUserNS = false
	} else if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(data)) == "0" && os.Geteuid() != 0 {
			caps.HasUserNS = false
		}
	}

	// 4. Probe Landlock LSM
	// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
	const landlockCreateRulesetVersion = 1 << 0
	res, _, err := unix.Syscall(
		sysLandlockCreateRuleset,
		0,
		0,
		uintptr(landlockCreateRulesetVersion),
	)
	if err == 0 && int(res) > 0 {
		caps.HasLandlock = true
	} else if err == unix.EOPNOTSUPP || err == unix.ENOSYS {
		caps.HasLandlock = false
	} else {
		// Kernel might support landlock ABI but ruleset query differed
		caps.HasLandlock = (err != unix.ENOSYS)
	}

	caps.Details = fmt.Sprintf("linux [seccomp:%v, mountns:%v, userns:%v, landlock:%v]",
		caps.HasSeccomp, caps.HasMountNS, caps.HasUserNS, caps.HasLandlock)
	return caps
}

// Unused dummy syscall ref to prevent unused import warnings if needed
var _ = unsafe.Sizeof(0)
var _ = syscall.SIGKILL
