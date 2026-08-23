//go:build !linux

package jail

func ApplyLandlockLockdown(allowedPaths []string) error {
	return nil
}
