package volume

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// removeCreds must tolerate an already-absent file (idempotent) and
// report every other failure — here a non-empty directory cannot be
// unlinked — instead of swallowing it.
func TestRemoveCredsReportsFailures(t *testing.T) {
	if err := removeCreds(filepath.Join(t.TempDir(), "absent.creds")); err != nil {
		t.Fatalf("missing creds file must be tolerated, got %v", err)
	}
	blocker := filepath.Join(t.TempDir(), ".s3-vol1.creds")
	if err := os.Mkdir(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocker, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := removeCreds(blocker)
	if err == nil || !strings.Contains(err.Error(), "credentials file") {
		t.Fatalf("non-removable creds path must be reported, got %v", err)
	}
}

// A prior process instance that died between Attach's passwd write and
// its deferred remove leaves an orphan .creds file. Detach on the last
// node ref — even from a process that never saw the Attach — must
// recover the mountpoint from the replayed metadata, confirm no active
// mount, and sweep the orphan.
func TestS3DetachSweepsOrphanCredsFromPriorInstance(t *testing.T) {
	if _, err := exec.LookPath("fusermount"); err != nil {
		t.Skip("fusermount not available")
	}
	base := t.TempDir()
	orphan := filepath.Join(base, ".s3-vol1.creds")
	if err := os.WriteFile(orphan, []byte("AKIA:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewS3("s3") // fresh process: no attach bookkeeping at all
	mnt := filepath.Join(base, "s3-vol1")
	err := p.Detach(context.Background(), &DetachRequest{
		VolumeID: "vol1", NodeRefLastDetach: true,
		Metadata: map[string]string{"hostPath": mnt},
	})
	if err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan creds file must be swept, stat err = %v", err)
	}
}

// Same-process detach must also report (not swallow) a failure to
// remove the credentials file beside the recorded mountpoint.
func TestS3DetachReportsCredsRemoveFailure(t *testing.T) {
	if _, err := exec.LookPath("fusermount"); err != nil {
		t.Skip("fusermount not available")
	}
	base := t.TempDir()
	blocker := filepath.Join(base, ".s3-vol1.creds")
	if err := os.Mkdir(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocker, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewS3("s3")
	p.mnts["vol1"] = filepath.Join(base, "s3-vol1")
	err := p.Detach(context.Background(), &DetachRequest{
		VolumeID: "vol1", NodeRefLastDetach: true,
	})
	if err == nil || !strings.Contains(err.Error(), "credentials file") {
		t.Fatalf("creds remove failure must be reported, got %v", err)
	}
}

// Detach with no mountpoint on record anywhere (no bookkeeping, no
// replayed metadata) stays a clean no-op.
func TestS3DetachWithoutAnyRecordIsNoop(t *testing.T) {
	p := NewS3("s3")
	if err := p.Detach(context.Background(), &DetachRequest{
		VolumeID: "vol1", NodeRefLastDetach: true,
	}); err != nil {
		t.Fatalf("detach without any record must be a no-op, got %v", err)
	}
}
