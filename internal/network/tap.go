package network

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"unsafe"

	"golang.org/x/sys/unix"
)

func CreateTap(name string) error {
	cmd := exec.Command("ip", "tuntap", "add", "mode", "tap", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create tap %s: %v", name, err)
	}

	cmd = exec.Command("ip", "link", "set", name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up tap %s: %v", name, err)
	}

	return nil
}

// TAP ioctl numbers and flags (Linux UAPI, identical on x86_64/aarch64).
// Defined locally as literals so this file compiles on every arch x/sys/unix
// supports; the same values appear in internal/jail/seccomp_filter.go (the
// workload-side ioctl allowlist) — keep them in sync.
const (
	ioctlTUNSETIFF = 0x400454CA

	iffTAP  = 0x0002
	iffNOPI = 0x1000
)

// ifNameRe guards the ifreq buffer: IFNAMSIZ is 16 including the NUL, and
// '/', whitespace and ':'/',' would additionally corrupt kernel-cmdline
// fields downstream.
var ifNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// ifreqFlags is the TUNSETIFF request body: char ifr_name[IFNAMSIZ] followed
// by the flags short at the fixed offset (struct ifreq, ifr_flags).
type ifreqFlags struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_     [22]byte // pad to sizeof(struct ifreq) — union space is unused
}

// OpenTapFD attaches a tap device host-side and returns the open fd, ready
// to be inherited by the jailed UML kernel as vec0:transport=fd,fd=N,vec=0.
//
// This is the manager-side half of the rootless tap plan (TODO.md "[P1]
// Jail rootless 化"): attaching a tap requires CAP_NET_ADMIN in the HOST
// network namespace, which a namespaced-root monitor does not have — so the
// manager (real root) performs open("/dev/net/tun") + TUNSETIFF here and
// the workload receives only the finished fd. Inside the jail nothing needs
// /dev/net/tun, CAP_NET_ADMIN or the TUN* ioctls anymore.
//
// Two UML fd-transport facts drive the exact shape (CI bisect 8856):
//   - transport=fd defaults to VECTOR mode (VECTOR_RX|VECTOR_TX), whose TX
//     path is sendmmsg(2) — SOCKETS only; on a tap char device every TX
//     fails ENOTSOCK and vec0 dies on the first frame. vec=0 forces
//     packet-at-a-time readv/writev, the only mode that works on tap fds.
//   - the fd transport speaks raw ethernet frames (header_size=0), so the
//     fd must be attached WITHOUT IFF_VNET_HDR — unlike the "tap"
//     transport, which enables vnet headers on the fd it opens itself.
//
// Attaching to a PRE-CREATED tap (operator-managed, possibly bridged) works
// unchanged: TUNSETIFF with an existing ifname attaches to it. When name
// does not exist, the kernel creates a transient tap whose lifetime is tied
// to the fd — it disappears when the monitor exits, which is the desired
// cleanup semantics.
func OpenTapFD(name string) (*os.File, error) {
	if !ifNameRe.MatchString(name) {
		return nil, fmt.Errorf("network: invalid tap name %q", name)
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("network: open /dev/net/tun: %w", err)
	}
	fail := func(err error) (*os.File, error) {
		_ = f.Close()
		return nil, err
	}

	// Attach WITHOUT IFF_VNET_HDR, and no TUNSETOFFLOAD/TUNSETVNETHDRSZ:
	// UML's fd transport (arch/um/drivers/vector_*) keeps header_size=0 and
	// speaks RAW ethernet frames on the fd — the virtio-net header machinery
	// is exclusive to the self-attaching "tap" transport. A vnet-enabled fd
	// would have the first 10 bytes of every frame misparsed as a header.
	req := ifreqFlags{flags: iffTAP | iffNOPI}
	copy(req.name[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), ioctlTUNSETIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fail(fmt.Errorf("network: TUNSETIFF %s: %w", name, errno))
	}

	// A transiently created tap starts link-down; a pre-created one is
	// already up (idempotent either way).
	if out, err := exec.Command("ip", "link", "set", name, "up").CombinedOutput(); err != nil {
		return fail(fmt.Errorf("network: bring up tap %s: %v (%s)", name, err, out))
	}
	return f, nil
}
