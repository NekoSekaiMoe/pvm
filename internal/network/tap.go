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
	ioctlTUNSETIFF       = 0x400454CA
	ioctlTUNGETFEATURES  = 0x800454CF
	ioctlTUNSETOFFLOAD   = 0x400454D0
	ioctlTUNSETVNETHDRSZ = 0x400454D8

	iffTAP     = 0x0002
	iffNOPI    = 0x1000
	iffVNETHDR = 0x4000

	tunFCSUM = 0x01
	tunFTSO4 = 0x02
	tunFTSO6 = 0x04

	// virtioNetHdrLen is sizeof(struct virtio_net_hdr) — the value UML's
	// vector tap setup programs via TUNSETVNETHDRSZ
	// (arch/um/drivers/vector_user.c uml_tap_enable_vnet_headers).
	virtioNetHdrLen = 10
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
// to be inherited by the jailed UML kernel as vec0:transport=fd,fd=N.
//
// This is the manager-side half of the rootless tap plan (TODO.md "[P1]
// Jail rootless 化"): attaching a tap requires CAP_NET_ADMIN in the HOST
// network namespace, which a namespaced-root monitor does not have — so the
// manager (real root) performs open("/dev/net/tun") + TUNSETIFF + offload /
// vnet-header setup here, mirroring exactly what UML's vector tap transport
// would have done in create_tap_fd()/uml_tap_enable_vnet_headers(), and the
// workload receives only the finished fd. Inside the jail nothing needs
// /dev/net/tun, CAP_NET_ADMIN or the TUN* ioctls anymore.
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

	req := ifreqFlags{flags: iffTAP | iffNOPI | iffVNETHDR}
	copy(req.name[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), ioctlTUNSETIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fail(fmt.Errorf("network: TUNSETIFF %s: %w", name, errno))
	}

	// Same capability probe UML does before enabling vnet headers; without
	// the feature the guest driver would mis-parse frames.
	var features uint32
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), ioctlTUNGETFEATURES, uintptr(unsafe.Pointer(&features))); errno != 0 {
		return fail(fmt.Errorf("network: TUNGETFEATURES %s: %w", name, errno))
	}
	if features&iffVNETHDR == 0 {
		return fail(fmt.Errorf("network: tap %s lacks IFF_VNET_HDR support", name))
	}

	offload := tunFCSUM | tunFTSO4 | tunFTSO6
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), ioctlTUNSETOFFLOAD, uintptr(offload)); errno != 0 {
		return fail(fmt.Errorf("network: TUNSETOFFLOAD %s: %w", name, errno))
	}
	hdrLen := virtioNetHdrLen
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), ioctlTUNSETVNETHDRSZ, uintptr(unsafe.Pointer(&hdrLen))); errno != 0 {
		return fail(fmt.Errorf("network: TUNSETVNETHDRSZ %s: %w", name, errno))
	}

	// A transiently created tap starts link-down; a pre-created one is
	// already up (idempotent either way).
	if out, err := exec.Command("ip", "link", "set", name, "up").CombinedOutput(); err != nil {
		return fail(fmt.Errorf("network: bring up tap %s: %v (%s)", name, err, out))
	}
	return f, nil
}
