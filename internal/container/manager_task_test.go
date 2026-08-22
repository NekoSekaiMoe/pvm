package container

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"uml-container/internal/audit"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/uml"
)

// trackingLauncher records the kernel/args it was started with and never blocks.
type trackingLauncher struct {
	kernel string
	args   []string
	pid    int
}

func (t *trackingLauncher) Start(ctx context.Context, kernel string, args []string, logFile *os.File) (int, *uml.Process, error) {
	t.kernel = kernel
	t.args = args
	return 999, &uml.Process{}, nil
}
func (t *trackingLauncher) Wait(*uml.Process) error { return nil }

func newTestManager(t *testing.T) (*Manager, *trackingLauncher) {
	t.Helper()
	state.RootDir = t.TempDir()
	audit.LedgerRoot = t.TempDir()
	os.Setenv("PVM_CGROUP_ROOT", t.TempDir()) // throwaway, no real cgroup writes
	tl := &trackingLauncher{pid: 999}
	return &Manager{Launcher: tl}, tl
}

func minimalSpec(baseImage string) *spec.TaskSpec {
	return &spec.TaskSpec{
		Version:   1,
		Caller:    "alice",
		Tenant:    "eng",
		Runtime:   spec.RuntimeSpec{Name: "task-x", CPU: 1, Memory: "256M"},
		Workspace: spec.WorkspaceSpec{BaseImage: baseImage, Init: "/sbin/init"}, // ubd path mounts this verbatim
		Kernel:    spec.KernelSpec{Path: "/usr/lib/uml/linux"},
		Network:   spec.NetworkSpec{Enabled: false},
		Lifecycle: spec.LifecycleSpec{OnAnomaly: "pause"},
	}
}

// testBaseImage materializes a real raw image inside a directory registered
// as the test's trusted image root (PVM_IMAGE_ROOT). validateRootfs/
// validateRootfsContained reject nonexistent or out-of-root images, so every
// StartTask test must mount an actual file — not a hardcoded /tmp path that
// may or may not exist on the host.
func testBaseImage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PVM_IMAGE_ROOT", dir)
	p := filepath.Join(dir, "base.img")
	if err := os.WriteFile(p, make([]byte, 4096), 0o600); err != nil {
		t.Fatalf("write base image: %v", err)
	}
	return p
}

func TestStartTask_DrivesFSM(t *testing.T) {
	m, tl := newTestManager(t)
	s := minimalSpec(testBaseImage(t))

	if err := m.StartTask(context.Background(), "task-x", s); err != nil {
		t.Fatalf("starttask: %v", err)
	}
	if tl.kernel != "/usr/lib/uml/linux" {
		t.Errorf("kernel = %s", tl.kernel)
	}
	st, err := state.LoadState("task-x")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	// Should have landed in Review (clean exit, awaiting artifact gate).
	if st.Status != state.StatusReview {
		t.Errorf("status = %s, want review", st.Status)
	}
	// FSM must have recorded the full path Pending->Provisioning->Ready->Running->Review
	if len(st.Transitions) < len(wantSequence) {
		t.Fatalf("only %d transitions recorded: %+v", len(st.Transitions), st.Transitions)
	}
	for i, want := range wantSequence {
		if st.Transitions[i].To != want {
			t.Errorf("transition[%d].To = %s, want %s", i, st.Transitions[i].To, want)
		}
	}
	if st.SpecFP == "" {
		t.Error("spec fingerprint not recorded on state")
	}
}

// wantSequence mirrors the expected FSM path for a clean StartTask run.
var wantSequence = []state.Status{
	state.StatusProvisioning,
	state.StatusReady,
	state.StatusRunning,
	state.StatusReview,
}

func TestStartTask_RecordsAuditAndFingerprint(t *testing.T) {
	m, _ := newTestManager(t)
	s := minimalSpec(testBaseImage(t))

	_ = m.StartTask(context.Background(), "task-y", s)

	l, err := audit.Open("task-y")
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	records, err := l.ReadAll()
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("audit ledger is empty after StartTask")
	}
	// phase 02 (SPEC+VERSION) must be recorded.
	var sawSpec bool
	for _, r := range records {
		if r.Phase == audit.PhaseSpec {
			sawSpec = true
		}
	}
	if !sawSpec {
		t.Error("expected a PhaseSpec audit record (SPEC+VERSION evidence)")
	}
}

// TestStartTask_RawBaseUbdDirectMount verifies the ubd path (UseVhostBlk=false):
// the raw BaseImage is mounted directly as ubd0=<base> with no qcow2 CoW layer.
// This is the verified-working configuration for networking — vec0 (the
// coexists with ubd0 but not with virtio_uml block (see the TODO in
// buildTaskArgs). The kernel cmdline must reference the base file verbatim.
func TestStartTask_RawBaseUbdDirectMount(t *testing.T) {
	m, tl := newTestManager(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "rootfs.img")
	if err := os.WriteFile(base, make([]byte, 1<<20), 0644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	// The temp dir must be a trusted image root, and the assertion below
	// must use the symlink-resolved path: validateRootfsContained boots the
	// resolved file, which can differ from the lexical temp path.
	t.Setenv("PVM_IMAGE_ROOT", dir)
	resolvedBase, rerr := filepath.EvalSymlinks(base)
	if rerr != nil {
		t.Fatalf("resolve base: %v", rerr)
	}

	s := minimalSpec(base)
	s.Workspace.BaseImage = base
	s.Kernel.UseVhostBlk = false // ubd path: raw base mounted directly, no CoW

	if err := m.StartTask(context.Background(), "task-ubd", s); err != nil {
		t.Fatalf("starttask ubd path: %v", err)
	}
	// The kernel cmdline must carry ubd0=<resolved base> directly (no overlay
	// created).
	found := false
	for _, a := range tl.args {
		if a == "ubd0="+resolvedBase {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("raw base not mounted directly via ubd0; kernel args = %v", tl.args)
	}
}

// TestStartTask_OverlayFailureFailsClosed verifies that when BaseImage IS
// qcow2 and vhost IS enabled, an overlay-creation failure still fails closed
// rather than degrading to a writable mount of the shared base. We force the
// failure with a backing path that passes validatePath but not os.Stat; no
// qemu-img / qemu-storage-daemon needed.
func TestStartTask_OverlayFailureFailsClosed(t *testing.T) {
	m, _ := newTestManager(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "does-not-exist.qcow2") // absent: os.Stat fails

	s := minimalSpec(base)
	s.Workspace.BaseImage = base
	s.Workspace.Overlay = filepath.Join(dir, "ov.qcow2")
	s.Kernel.UseVhostBlk = true // correct config; only the backing file is missing

	err := m.StartTask(context.Background(), "task-z", s)
	if err == nil {
		t.Fatal("expected StartTask to fail when qcow2 overlay creation fails")
	}
	st, ferr := state.LoadState("task-z")
	if ferr != nil {
		t.Fatalf("load state: %v", ferr)
	}
	if st.Status != state.StatusFailed {
		t.Errorf("status = %s, want failed (unsafe fallback would leave it running)", st.Status)
	}
}
