package container

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uml-container/internal/audit"
	"uml-container/internal/jail"
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

func (t *trackingLauncher) Start(ctx context.Context, kernel string, args []string, logFile io.Writer) (int, *uml.Process, error) {
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
	jail.ResetHostCapabilitiesForTest(&jail.HostCapabilities{
		HasLandlock: true,
		HasUserNS:   true,
		HasMountNS:  true,
		HasSeccomp:  true,
		Details:     "test-simulated-full",
	})
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

// wantSequence mirrors the expected FSM path for a clean StartTask run.
var wantSequence = []state.Status{
	state.StatusProvisioning,
	state.StatusReady,
	state.StatusRunning,
	state.StatusReview,
}

// TestStartTask is the table-driven form of the StartTask flow tests: the
// clean success run (FSM transitions + kernel args), the ubd raw-base direct
// mount, and the overlay failure / vhost backing-image validation paths.
// Each case reuses the same newTestManager → minimalSpec → StartTask
// pipeline; case-specific setup and assertions live in the table's
// setup/assert closures.
func TestStartTask(t *testing.T) {
	tests := []struct {
		name    string
		taskID  string
		wantErr bool
		// setup builds the spec for the case (and any case-specific
		// fixtures, e.g. a trusted image root via t.Setenv).
		setup func(t *testing.T) *spec.TaskSpec
		// assert verifies the outcome; it runs only after the wantErr
		// expectation itself was checked by the driver below. err is the
		// StartTask error (nil unless wantErr).
		assert func(t *testing.T, tl *trackingLauncher, s *spec.TaskSpec, taskID string, err error)
	}{
		{
			name:   "success drives FSM to review",
			taskID: "task-x",
			setup: func(t *testing.T) *spec.TaskSpec {
				return minimalSpec(testBaseImage(t))
			},
			assert: func(t *testing.T, tl *trackingLauncher, _ *spec.TaskSpec, taskID string, _ error) {
				if tl.kernel != "/usr/lib/uml/linux" {
					t.Errorf("kernel = %s", tl.kernel)
				}
				st, err := state.LoadState(taskID)
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
			},
		},
		{
			// ubd path (UseVhostBlk=false): the raw BaseImage is mounted
			// directly as ubd0=<base> with no qcow2 CoW layer. This is the
			// verified-working configuration for networking — vec0 (the
			// coexists with ubd0 but not with virtio_uml block (see the TODO
			// in buildTaskArgs). The kernel cmdline must reference the base
			// file verbatim.
			name:   "raw base ubd direct mount",
			taskID: "task-ubd",
			setup: func(t *testing.T) *spec.TaskSpec {
				dir := t.TempDir()
				base := filepath.Join(dir, "rootfs.img")
				if err := os.WriteFile(base, make([]byte, 1<<20), 0644); err != nil {
					t.Fatalf("write base: %v", err)
				}
				// The temp dir must be a trusted image root; the assertion
				// below resolves the symlink-free path itself:
				// validateRootfsContained boots the resolved file, which can
				// differ from the lexical temp path.
				t.Setenv("PVM_IMAGE_ROOT", dir)
				return minimalSpec(base)
			},
			assert: func(t *testing.T, tl *trackingLauncher, s *spec.TaskSpec, _ string, _ error) {
				if _, rerr := filepath.EvalSymlinks(s.Workspace.BaseImage); rerr != nil {
					t.Fatalf("resolve base: %v", rerr)
				}
				// The jail is active in tests (TestMain pins capabilities), so
				// the kernel cmdline carries the IN-JAIL bind-mount path; the
				// resolved base path moves into the jail volume mapping. The
				// point of this case — no overlay, base mounted directly via
				// ubd0 — is preserved: ubd0= (not ubd0r=) is present.
				found := false
				for _, a := range tl.args {
					if a == "ubd0="+jailGuestRootfs {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("raw base not mounted directly via ubd0; kernel args = %v", tl.args)
				}
			},
		},
		{
			// Optional fields (review fix): Runtime.Memory and BaseImage are
			// optional — a spec that leaves both unset must pass the hoisted
			// validation in StartTask and boot init-only, emitting NO mem=/
			// ubd0=/root= kernel args (empty mem= or ubd0= would be a broken
			// kernel parameter).
			name:   "optional memory and rootfs omitted",
			taskID: "task-opt",
			setup: func(t *testing.T) *spec.TaskSpec {
				s := minimalSpec("")
				s.Runtime.Memory = ""
				return s
			},
			assert: func(t *testing.T, tl *trackingLauncher, _ *spec.TaskSpec, taskID string, _ error) {
				for _, a := range tl.args {
					if strings.HasPrefix(a, "mem=") || strings.HasPrefix(a, "ubd0=") || strings.HasPrefix(a, "root=") {
						t.Errorf("unset optional field emitted kernel arg %q: %v", a, tl.args)
					}
				}
				joined := strings.Join(tl.args, "\n")
				if !strings.Contains(joined, "init=/sbin/init") || !strings.Contains(joined, "rw") {
					t.Errorf("base args missing: %v", tl.args)
				}
				st, ferr := state.LoadState(taskID)
				if ferr != nil {
					t.Fatalf("load state: %v", ferr)
				}
				if st.Status != state.StatusReview {
					t.Errorf("status = %s, want review", st.Status)
				}
			},
		},
		{
			// Overlay failure fails closed: when vhost IS enabled, a backing
			// path that cannot be used (here: absent and outside the trusted
			// roots, so it fails validation before CreateOverlay even runs)
			// must fail the task rather than degrade to a writable mount of
			// the shared base. No qemu-img / qemu-storage-daemon needed.
			name:    "overlay failure fails closed",
			taskID:  "task-z",
			wantErr: true,
			setup: func(t *testing.T) *spec.TaskSpec {
				dir := t.TempDir()
				base := filepath.Join(dir, "does-not-exist.qcow2") // absent: fails closed
				s := minimalSpec(base)
				s.Workspace.Overlay = filepath.Join(dir, "ov.qcow2")
				s.Kernel.UseVhostBlk = true // correct config; only the backing file is missing
				return s
			},
			assert: func(t *testing.T, _ *trackingLauncher, _ *spec.TaskSpec, taskID string, _ error) {
				st, ferr := state.LoadState(taskID)
				if ferr != nil {
					t.Fatalf("load state: %v", ferr)
				}
				if st.Status != state.StatusFailed {
					t.Errorf("status = %s, want failed (unsafe fallback would leave it running)", st.Status)
				}
			},
		},
		{
			// vhost backing-image symlink escape: a symlink inside a trusted
			// image root that resolves OUTSIDE the roots must be rejected
			// BEFORE cow.CreateOverlay runs — the overlay file (defaulted
			// under the task's container dir) must never be created and the
			// task must land in Failed.
			name:    "vhost base image symlink escape rejected",
			taskID:  "task-esc",
			wantErr: true,
			setup: func(t *testing.T) *spec.TaskSpec {
				outside := t.TempDir()
				real := filepath.Join(outside, "real.img")
				if err := os.WriteFile(real, make([]byte, 4096), 0o600); err != nil {
					t.Fatalf("write outside base: %v", err)
				}
				root := t.TempDir()
				t.Setenv("PVM_IMAGE_ROOT", root)
				link := filepath.Join(root, "escape.img")
				if err := os.Symlink(real, link); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				s := minimalSpec(link)
				s.Kernel.UseVhostBlk = true
				return s // Workspace.Overlay empty → default <containerDir>/rootfs.qcow2
			},
			assert: func(t *testing.T, _ *trackingLauncher, _ *spec.TaskSpec, taskID string, err error) {
				// The rejection must come from the trusted-root gate BEFORE
				// CreateOverlay — not from a later overlay/daemon failure whose
				// deferred cleanup would remove the evidence anyway.
				if err == nil || !strings.Contains(err.Error(), "failed trusted-root validation") {
					t.Errorf("want a trusted-root validation error, got: %v", err)
				}
				dir, derr := state.ContainerDir(taskID)
				if derr != nil {
					t.Fatalf("container dir: %v", derr)
				}
				overlay := filepath.Join(dir, "rootfs.qcow2")
				if _, serr := os.Stat(overlay); !os.IsNotExist(serr) {
					t.Errorf("overlay %s created despite validation failure (CreateOverlay must not run)", overlay)
				}
				st, ferr := state.LoadState(taskID)
				if ferr != nil {
					t.Fatalf("load state: %v", ferr)
				}
				if st.Status != state.StatusFailed {
					t.Errorf("status = %s, want failed", st.Status)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, tl := newTestManager(t)
			s := tt.setup(t)
			err := m.StartTask(context.Background(), tt.taskID, s)
			if tt.wantErr != (err != nil) {
				t.Fatalf("starttask error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				// The error must name the offending base image and/or task so
				// an operator can see WHICH path was rejected and why.
				if !strings.Contains(err.Error(), s.Workspace.BaseImage) && !strings.Contains(err.Error(), tt.taskID) {
					t.Errorf("error should name the offending path or task: %v", err)
				}
			}
			tt.assert(t, tl, s, tt.taskID, err)
		})
	}
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
