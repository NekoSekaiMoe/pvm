package jail

// SockFilter describes a single classic BPF instruction. It mirrors
// unix.SockFilter so that BuildUMLSeccompFilter can be compiled and unit
// tested on non-Linux platforms where unix.SockFilter is unavailable.
type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// ioctl request numbers (Linux UAPI, identical on x86_64/aarch64) permitted
// by the second-stage argument filter that BuildUMLSeccompFilter emits for
// the ioctl syscall. They are defined locally as literals so this shared
// file compiles on non-Linux platforms where x/sys/unix lacks them.
const (
	// Terminal handling (UML console stdio)
	ioctlTCGETS     = 0x5401
	ioctlTCSETS     = 0x5402
	ioctlTCSETSW    = 0x5403
	ioctlTCSETSF    = 0x5404
	ioctlTIOCGWINSZ = 0x5413
	ioctlTIOCSWINSZ = 0x5414

	// fd/socket readiness and non-blocking toggles
	ioctlFIONREAD = 0x541B
	ioctlFIONBIO  = 0x5421

	// TAP attach for vec0 transport=tap (reachable only if /dev/net/tun is
	// ever made visible inside the jail; the device node itself is gated by
	// the jail filesystem view)
	ioctlTUNSETIFF     = 0x400454CA
	ioctlTUNSETPERSIST = 0x400454CB
	ioctlTUNSETOWNER   = 0x400454CC
	ioctlTUNSETGROUP   = 0x400454CE
	ioctlTUNSETQUEUE   = 0x400454D9
	// UML vector tap setup probes device capabilities and configures the
	// vnet header after TUNSETIFF (arch/um/drivers/vector_user.c). Without
	// TUNGETFEATURES the setup fails with EPERM and UML's error path
	// (vector_net_close on a half-initialized device) NULL-derefs into a
	// guest panic — CI run 88461751142, pkg-install and qcow2 tests.
	ioctlTUNGETFEATURES  = 0x800454CF
	ioctlTUNSETOFFLOAD   = 0x400454D0
	ioctlTUNSETVNETHDRSZ = 0x400454D8

	// Read-only interface getters (UML tap setup queries the pre-created
	// host TAP's flags/MTU/MAC/index)
	ioctlSIOCGIFFLAGS  = 0x8913
	ioctlSIOCGIFMTU    = 0x8921
	ioctlSIOCGIFHWADDR = 0x8927
	ioctlSIOCGIFINDEX  = 0x8933
)

// allowedIoctlRequests is the second-stage allowlist for ioctl: the syscall
// number alone is too coarse (ioctl multiplexes the entire kernel driver
// surface onto one number), so the filter additionally compares the request
// argument against this list. Setters (SIOCSIF*), device-private commands
// and everything else fall to ERRNO(EPERM). Entries must stay read-only /
// jail-scoped; widening this list is a security-review-level change.
var allowedIoctlRequests = []uint32{
	ioctlTCGETS, ioctlTCSETS, ioctlTCSETSW, ioctlTCSETSF,
	ioctlTIOCGWINSZ, ioctlTIOCSWINSZ,
	ioctlFIONREAD, ioctlFIONBIO,
	ioctlTUNSETIFF, ioctlTUNSETPERSIST, ioctlTUNSETOWNER, ioctlTUNSETGROUP, ioctlTUNSETQUEUE,
	ioctlTUNGETFEATURES, ioctlTUNSETOFFLOAD, ioctlTUNSETVNETHDRSZ,
	ioctlSIOCGIFFLAGS, ioctlSIOCGIFMTU, ioctlSIOCGIFHWADDR, ioctlSIOCGIFINDEX,
}
