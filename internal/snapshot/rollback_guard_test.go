package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uml-container/internal/cow"
	"uml-container/internal/state"
)

// setupStateRoot redirects the snapshot package's state root AND the cow
// backing-containment roots (read from the environment at call time) into
// one temp tree, so overlay chains built there open cleanly.
func setupStateRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	oldRoot := state.RootDir
	state.RootDir = root
	t.Cleanup(func() { state.RootDir = oldRoot })
	t.Setenv("PVM_STATE_ROOT", root)
	t.Setenv("PVM_COW_ROOT", filepath.Join(root, "cow"))
	return root
}

// buildOverlayChain lays out <dir>/rootfs.img (raw base) → <dir>/overlay.qcow2
// (live overlay), mirroring a real container's disk stack.
func buildOverlayChain(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 2<<20)
	for i := range raw {
		raw[i] = 'A'
	}
	base := filepath.Join(dir, "rootfs.img")
	if err := os.WriteFile(base, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := cow.CreateOverlay(context.Background(), base, filepath.Join(dir, "overlay.qcow2")); err != nil {
		t.Fatalf("CreateOverlay(base, live): %v", err)
	}
	return base
}

// writeSnapshot records <dir>/snapshots/<snapID>/ with an overlay branching
// from backingPath plus the minimal metadata Rollback reads. With
// backingPath = the live overlay it reproduces CreateEventSnapshot's shape;
// with a base image it produces a dependency shape without a live-path
// cycle (what the guard's semantics are about).
func writeSnapshot(t *testing.T, dir, snapID, backingPath string) string {
	t.Helper()
	snapDir := filepath.Join(dir, "snapshots", snapID)
	if err := os.MkdirAll(snapDir, 0755); err != nil {
		t.Fatal(err)
	}
	snapOv := filepath.Join(snapDir, "overlay.qcow2")
	if err := cow.CreateOverlay(context.Background(), backingPath, snapOv); err != nil {
		t.Fatalf("CreateOverlay(%s, snap): %v", backingPath, err)
	}
	meta, err := json.Marshal(EventSnapshot{ID: snapID, TaskID: filepath.Base(dir), StateStatus: "ready"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "snapshot.json"), meta, 0644); err != nil {
		t.Fatal(err)
	}
	return snapOv
}

// branchLiveOver replaces <dir>/overlay.qcow2 with a fresh overlay whose
// backing is backingPath (build via tmp + rename, like Rollback does).
func branchLiveOver(t *testing.T, dir, backingPath string) {
	t.Helper()
	tmp := filepath.Join(dir, ".tmp-branch.qcow2")
	_ = os.Remove(tmp)
	if err := cow.CreateOverlay(context.Background(), backingPath, tmp); err != nil {
		t.Fatalf("CreateOverlay(%s, tmp): %v", backingPath, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "overlay.qcow2")); err != nil {
		t.Fatal(err)
	}
}

// TestRollback_MakesOverlayStandalone pins the core rollback fix: the
// restored live overlay must be a STANDALONE image (no backing into the
// snapshot dir), so deleting the snapshot afterwards cannot break the live
// chain. This also proves the pre-fix pathologies are gone — the branch
// step's live→snap→live cycle and the copyFile fallback's self-reference
// would both leave a backing (or an unopenable image) here.
func TestRollback_MakesOverlayStandalone(t *testing.T) {
	root := setupStateRoot(t)
	task := "rb-task"
	dir := filepath.Join(root, task)
	buildOverlayChain(t, dir)
	snapOv := writeSnapshot(t, dir, "snap-rb-1", filepath.Join(dir, "overlay.qcow2"))

	if err := Rollback(task, "snap-rb-1"); err != nil {
		t.Fatalf("Rollback(%s, snap-rb-1): %v", task, err)
	}
	live := filepath.Join(dir, "overlay.qcow2")
	backing, err := cow.BackingOf(live)
	if err != nil {
		t.Fatalf("BackingOf(live) after rollback: %v", err)
	}
	if backing != "" {
		t.Fatalf("post-rollback live overlay still backs %q; want standalone", backing)
	}
	if _, err := os.Stat(snapOv); err != nil {
		t.Fatalf("snapshot overlay must survive the rollback: %v", err)
	}
	// No reference remains: the snapshot is freely deletable, and the live
	// overlay stays readable afterwards.
	if err := DeleteEventSnapshot(task, "snap-rb-1"); err != nil {
		t.Fatalf("DeleteEventSnapshot after flattened rollback: %v", err)
	}
	if _, err := cow.BackingOf(live); err != nil {
		t.Fatalf("live overlay unreadable after snapshot delete: %v", err)
	}
}

// TestDeleteEventSnapshot_VetoedByBranchChain covers the guarded shape: a
// live overlay that BRANCHES from the snapshot (dependency left by the
// pre-flattening rollback). Deletion must veto with ErrSnapshotInUse — via
// the chain-reach check, not the fail-closed scan path — and unlock once
// the dependent is flattened standalone.
func TestDeleteEventSnapshot_VetoedByBranchChain(t *testing.T) {
	root := setupStateRoot(t)
	task := "guard-task"
	dir := filepath.Join(root, task)
	base := buildOverlayChain(t, dir)
	// Snapshot backed by the BASE (not the live path): a dependent can
	// branch from it without creating a live→snap→live cycle.
	snapOv := writeSnapshot(t, dir, "snap-g-1", base)

	// Dependent shape: live overlay is a branch OF the snapshot.
	branchLiveOver(t, dir, snapOv)

	err := DeleteEventSnapshot(task, "snap-g-1")
	if !errors.Is(err, ErrSnapshotInUse) {
		t.Fatalf("DeleteEventSnapshot = %v; want ErrSnapshotInUse", err)
	}
	if !strings.Contains(err.Error(), "reaches snapshot") {
		t.Fatalf("veto should come from the chain-reach check, got: %v", err)
	}
	if _, serr := os.Stat(snapOv); serr != nil {
		t.Fatalf("guarded snapshot must survive the veto: %v", serr)
	}

	// Heal exactly the way the new Rollback does — flatten the snapshot
	// into a standalone live overlay — and deletion unlocks.
	tmp2 := filepath.Join(dir, ".tmp-heal.qcow2")
	if cerr := cow.ConvertToQcow2(context.Background(), snapOv, tmp2, cow.ConvertDefaultOpt); cerr != nil {
		t.Fatalf("ConvertToQcow2 heal: %v", cerr)
	}
	if err := os.Rename(tmp2, filepath.Join(dir, "overlay.qcow2")); err != nil {
		t.Fatal(err)
	}
	if err := DeleteEventSnapshot(task, "snap-g-1"); err != nil {
		t.Fatalf("DeleteEventSnapshot after heal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "snapshots", "snap-g-1")); !os.IsNotExist(err) {
		t.Fatalf("snapshot dir still present after delete: %v", err)
	}
}

// TestDeleteEventSnapshot_NoFalseVetoWithUnrelatedChains ensures the guard
// does not veto when sibling snapshots and clones exist whose chains never
// reach the target snapshot — and still vetoes (via chain reach) once the
// live overlay does.
func TestDeleteEventSnapshot_NoFalseVetoWithUnrelatedChains(t *testing.T) {
	root := setupStateRoot(t)
	task := "cs-task"
	dir := filepath.Join(root, task)
	base := buildOverlayChain(t, dir)
	live := filepath.Join(dir, "overlay.qcow2")
	// Event-like snapshots branch from the live overlay.
	writeSnapshot(t, dir, "snap-c-1", live) // the delete target
	writeSnapshot(t, dir, "snap-c-2", live) // sibling
	// Clone the task: the clone's overlay also branches from the live one.
	if err := Clone(task, "cs-clone"); err != nil {
		t.Fatalf("Clone(%s, cs-clone): %v", task, err)
	}

	// Live overlay branches from the base only — no chain reaches
	// snap-c-1, so deletion must pass despite the sibling and the clone.
	if err := DeleteEventSnapshot(task, "snap-c-1"); err != nil {
		t.Fatalf("DeleteEventSnapshot with unrelated chains = %v; want nil", err)
	}

	// Now branch the live overlay from a NEW base-backed snapshot: every
	// dependent chain (live, sibling, clone) reaches it — deletion vetoes.
	snap3 := writeSnapshot(t, dir, "snap-c-3", base)
	branchLiveOver(t, dir, snap3)
	err := DeleteEventSnapshot(task, "snap-c-3")
	if !errors.Is(err, ErrSnapshotInUse) {
		t.Fatalf("DeleteEventSnapshot = %v; want ErrSnapshotInUse", err)
	}
	if !strings.Contains(err.Error(), "reaches snapshot") {
		t.Fatalf("veto should come from the chain-reach check, got: %v", err)
	}
}
