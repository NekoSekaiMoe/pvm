// ephemeral_test.go — cross-plane integration for workspace.ephemeral
// (non-persistent sandboxes): spec → StartTask → FSM → audit, asserting the
// ephemeral contract end to end:
//   - the kernel cmdline boots "ro" (not "rw") and the ubd device is
//     marked device-read-only (ubd0r=),
//   - NO qcow2 overlay is ever created (the base is served read-only),
//   - the audit trail records the constrained rootfs decision.
package integrationtest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uml-container/internal/audit"
	"uml-container/internal/container"
	"uml-container/internal/spec"
	"uml-container/internal/state"
)

// hasArgToken reports whether args contains the exact standalone token
// (e.g. "ro"). Substring matching against a joined command line is
// meaningless here: root=/dev/ubda already contains "ro", so a broad
// Contains would pass even if the real ro argument regressed away.
func hasArgToken(args []string, token string) bool {
	for _, a := range args {
		if a == token {
			return true
		}
	}
	return false
}

// hasArgPrefix reports whether any argument starts with prefix (e.g.
// "ubd0r=", the UBD device-level read-only marker).
func hasArgPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

// assertEphemeralCmdline asserts the shared ephemeral kernel command-line
// contract as table-driven subtests, parameterized per backend: the exact
// standalone "ro" token (never "rw" — root=/dev/ubda contains "ro" as a
// substring but proves nothing about the mount mode), the backend's root
// device argument, and its block-device arguments (read-only marker present,
// plain writable marker absent). Backend-specific lifecycle, overlay and
// audit assertions stay in the calling tests — only the cmdline contract
// is shared.
func assertEphemeralCmdline(t *testing.T, args []string, backend, root, wantDev, noDev string) {
	t.Helper()
	cases := []struct {
		name string
		ok   bool
	}{
		{backend + ": standalone ro token", hasArgToken(args, "ro")},
		{backend + ": no rw token", !hasArgToken(args, "rw")},
		{backend + ": root device " + root, hasArgToken(args, root)},
		{backend + ": block device " + wantDev, hasArgPrefix(args, wantDev)},
		{backend + ": no writable device " + noDev, !hasArgPrefix(args, noDev)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !c.ok {
				t.Errorf("ephemeral %s cmdline contract violated: %v", backend, args)
			}
		})
	}
}

// TestFlow_EphemeralVhostNoOverlay drives StartTask with an ephemeral spec on
// the vhost path: the base image is validated and served read-only through a
// real vhost-user-blk socket (pure-Go backend), no overlay file appears in
// the task state dir, and the launcher sees root=/dev/vda + ro.
func TestFlow_EphemeralVhostNoOverlay(t *testing.T) {
	setupIsolatedRoots(t)
	baseDir := t.TempDir()
	t.Setenv("PVM_IMAGE_ROOT", baseDir)
	// A raw base large enough for the read-only backend to serve.
	base := filepath.Join(baseDir, "base.img")
	if err := os.WriteFile(base, make([]byte, 1<<20), 0600); err != nil {
		t.Fatal(err)
	}

	s := &spec.TaskSpec{
		Version: 1, Caller: "alice", Tenant: "eng",
		Runtime:   spec.RuntimeSpec{Name: "eph1", CPU: 1, Memory: "256M"},
		Workspace: spec.WorkspaceSpec{Init: "/sbin/init", BaseImage: base, Ephemeral: true},
		Kernel:    spec.KernelSpec{Path: "/usr/lib/uml/linux", UseVhostBlk: true},
		Network:   spec.NetworkSpec{Enabled: false},
		Lifecycle: spec.LifecycleSpec{OnAnomaly: "pause"},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("spec: %v", err)
	}

	l := &noOpLauncher{}
	mgr := &container.Manager{Launcher: l}
	if err := mgr.StartTask(context.Background(), "eph1", s); err != nil {
		t.Fatalf("starttask: %v", err)
	}

	// 1. Kernel cmdline contract (table-driven; see assertEphemeralCmdline).
	// vhost: root=/dev/vda behind virtio_uml.device=, never a ubd device.
	assertEphemeralCmdline(t, l.args, "vhost", "root=/dev/vda", "virtio_uml.device=", "ubd0")

	// 2. No overlay was created: the task dir must not contain rootfs.qcow2
	// (only state.json / logs / the transient vhost socket).
	dir, err := state.ContainerDir("eph1")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "rootfs.qcow2" || strings.HasSuffix(e.Name(), ".qcow2") {
			t.Errorf("ephemeral task created a qcow2 overlay: %s", e.Name())
		}
	}

	// 3. The base image itself is untouched (byte-for-byte).
	got, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1<<20 {
		t.Errorf("base image size changed: %d", len(got))
	}
	for i, b := range got {
		if b != 0 {
			t.Fatalf("base image mutated at offset %d", i)
		}
	}

	// 4. FSM reached Review (clean exit).
	st, _ := state.LoadState("eph1")
	if st.Status != state.StatusReview {
		t.Fatalf("status = %s, want review", st.Status)
	}

	// 5. Audit recorded the ephemeral rootfs decision.
	led, _ := audit.Open("eph1")
	recs, _ := led.ReadAll()
	sawEphemeral := false
	for _, r := range recs {
		if r.Action == "rootfs" && strings.Contains(r.Reason, "ephemeral") {
			sawEphemeral = true
		}
	}
	if !sawEphemeral {
		t.Error("no ephemeral rootfs audit record")
	}
}

// TestFlow_EphemeralUbdReadOnly: the ubd path (use_vhost_blk=false) mounts
// the base directly; ephemeral mode still boots "ro" and creates no overlay.
func TestFlow_EphemeralUbdReadOnly(t *testing.T) {
	setupIsolatedRoots(t)
	baseDir := t.TempDir()
	t.Setenv("PVM_IMAGE_ROOT", baseDir)
	base := filepath.Join(baseDir, "base.img")
	if err := os.WriteFile(base, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}

	s := &spec.TaskSpec{
		Version: 1, Caller: "alice", Tenant: "eng",
		Runtime:   spec.RuntimeSpec{Name: "eph2", CPU: 1, Memory: "256M"},
		Workspace: spec.WorkspaceSpec{Init: "/sbin/init", BaseImage: base, Ephemeral: true},
		Kernel:    spec.KernelSpec{Path: "/usr/lib/uml/linux", UseVhostBlk: false},
		Network:   spec.NetworkSpec{Enabled: false},
		Lifecycle: spec.LifecycleSpec{OnAnomaly: "pause"},
	}
	l := &noOpLauncher{}
	mgr := &container.Manager{Launcher: l}
	if err := mgr.StartTask(context.Background(), "eph2", s); err != nil {
		t.Fatalf("starttask: %v", err)
	}

	// Kernel cmdline contract (table-driven; see assertEphemeralCmdline).
	// ubd: root=/dev/ubda behind the device-level read-only marker ubd0r=,
	// never a plain (writable) ubd0= device.
	assertEphemeralCmdline(t, l.args, "ubd", "root=/dev/ubda", "ubd0r=", "ubd0=")

	// No overlay on the ubd path either (it never creates one, but the
	// ephemeral flag must not change that).
	dir, err := state.ContainerDir("eph2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "rootfs.qcow2")); err == nil {
		t.Error("ephemeral ubd task unexpectedly has rootfs.qcow2")
	}

	// Audit carries the ubd ephemeral variant.
	led, _ := audit.Open("eph2")
	recs, _ := led.ReadAll()
	sawEphemeral := false
	for _, r := range recs {
		if r.Action == "rootfs" && strings.Contains(r.Reason, "ephemeral") {
			sawEphemeral = true
		}
	}
	if !sawEphemeral {
		t.Error("no ephemeral rootfs audit record (ubd)")
	}
}

// TestFlow_EphemeralSpecRejected: StartTask fail-closes on specs whose
// ephemeral flag conflicts with overlay knobs (defense in depth — spec.Load
// already rejects this, but StartTask must not trust its caller).
func TestFlow_EphemeralSpecRejected(t *testing.T) {
	setupIsolatedRoots(t)
	baseDir := t.TempDir()
	t.Setenv("PVM_IMAGE_ROOT", baseDir)
	base := filepath.Join(baseDir, "base.img")
	if err := os.WriteFile(base, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	s := &spec.TaskSpec{
		Version: 1, Caller: "alice", Tenant: "eng",
		Runtime:   spec.RuntimeSpec{Name: "eph3", CPU: 1, Memory: "256M"},
		Workspace: spec.WorkspaceSpec{Init: "/sbin/init", BaseImage: base, Ephemeral: true, CompactOnExit: true},
		Kernel:    spec.KernelSpec{Path: "/usr/lib/uml/linux", UseVhostBlk: true},
		Network:   spec.NetworkSpec{Enabled: false},
		Lifecycle: spec.LifecycleSpec{OnAnomaly: "pause"},
	}
	mgr := &container.Manager{Launcher: &noOpLauncher{}}
	if err := mgr.StartTask(context.Background(), "eph3", s); err == nil {
		// StartTask re-validates the spec before provisioning; the conflicting
		// combination must fail closed.
		t.Fatal("StartTask accepted ephemeral+compact_on_exit spec")
	}
}
