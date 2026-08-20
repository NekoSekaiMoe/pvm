package cow

import (
	"testing"
)

// openGuestImageFile is a test helper that opens path via openGuestImage and
// fails the test on error. Defined here (not in qcow2_test.go) so the compact
// tests and the older tests share one helper without a cross-file dependency
// that surprises readers.
func openGuestImageFile(t *testing.T, path string) guestImage {
	t.Helper()
	img, err := openGuestImage(path)
	if err != nil {
		t.Fatalf("openGuestImage %s: %v", path, err)
	}
	return img
}
