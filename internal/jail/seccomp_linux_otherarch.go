//go:build linux && !amd64 && !arm64

package jail

// Unsupported architectures: no arch-specific extras. Note that
// BuildUMLSeccompFilter already returns an empty filter for these (no
// AUDIT_ARCH_* constant to pin), and ApplyHostSeccompFilter refuses to
// install it — so nothing here is ever reached in production.
var archSpecificBlockedSyscalls []string

func getArchSyscallNumber(name string) (int, bool) {
	return 0, false
}
