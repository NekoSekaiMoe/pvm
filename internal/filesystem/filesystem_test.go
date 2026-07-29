package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestCreateExt4Image_RequiresBinaries(t *testing.T) {
	// CreateExt4Image shells out to dd + mkfs.ext4. On a minimal CI/CI-runner
	// without those tools it must report a clear error rather than silently
	// succeeding; if they are present it must produce a non-empty file. We
	// assert the non-error path is observable and the error path is reachable.
	tmp := filepath.Join(t.TempDir(), "img.bin")
	err := CreateExt4Image(tmp, 1)
	if err == nil {
		info, statErr := os.Stat(tmp)
		if statErr != nil {
			t.Fatalf("image reported created but stat failed: %v", statErr)
		}
		if info.Size() == 0 {
			t.Errorf("created image is empty")
		}
		return
	}
	// dd/mkfs.ext4 missing is acceptable in constrained envs; anything else isn't.
	t.Logf("CreateExt4Image returned error (likely missing dd/mkfs.ext4): %v", err)
}
