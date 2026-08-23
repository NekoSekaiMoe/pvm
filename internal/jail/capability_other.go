//go:build !linux

package jail

// DropDangerousCapabilities is a no-op on non-Linux platforms (capabilities
// are a Linux primitive); it keeps the jail helper's call sites compiling
// everywhere.
func DropDangerousCapabilities() error {
	return nil
}
