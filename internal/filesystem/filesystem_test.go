package filesystem

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireExt4Tools skips the test when the external binaries
// CreateExt4Image shells out to (dd, mkfs.ext4) are unavailable, e.g. on a
// minimal CI runner. With both present every CreateExt4Image error is fatal.
func requireExt4Tools(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"dd", "mkfs.ext4"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available: %v", bin, err)
		}
	}
}

func TestSetupOverlayfs_CreatesAllDirs(t *testing.T) {
	base := t.TempDir()
	// Use a subdir that doesn't exist yet to prove MkdirAll creates the chain.
	base = filepath.Join(base, "container")

	if err := SetupOverlayfs(base); err != nil {
		t.Fatalf("SetupOverlayfs: %v", err)
	}

	for _, d := range []string{"upper", "work", "merged"} {
		info, err := os.Stat(filepath.Join(base, d))
		if err != nil {
			t.Errorf("expected dir %s to exist: %v", d, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", d)
		}
	}
}

func TestCreateExt4Image(t *testing.T) {
	tests := []struct {
		name string
		// relative makes the image path relative; CreateExt4Image must
		// reject it before invoking any external tool.
		relative bool
		// wantErr asserts the call fails (used by the relative-path case).
		wantErr bool
		// checkPerm asserts the created image keeps mode 0600 (dd/mkfs must
		// not widen the mode the O_EXCL create set).
		checkPerm bool
	}{
		{name: "rejects relative path", relative: true, wantErr: true},
		{name: "creates non-empty image"},
		{name: "keeps mode 0600", checkPerm: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The create-success scenarios need the real tools; the
			// relative-path case must fail before any tool is invoked, so it
			// runs regardless (and needs no binaries).
			if !tc.relative {
				requireExt4Tools(t)
			}

			path := filepath.Join(t.TempDir(), "img.bin")
			if tc.relative {
				path = "relative.img"
			}
			err := CreateExt4Image(path, 1)
			if tc.wantErr {
				if err == nil {
					t.Fatal("relative image path must be rejected")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateExt4Image: %v", err)
			}

			info, statErr := os.Stat(path)
			if statErr != nil {
				t.Fatalf("stat image: %v", statErr)
			}
			if info.Size() == 0 {
				t.Errorf("created image is empty")
			}
			if tc.checkPerm && info.Mode().Perm() != 0600 {
				t.Fatalf("image mode = %v, want 0600", info.Mode().Perm())
			}
		})
	}
}
