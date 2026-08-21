package cow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEngine_NameValidation_BlocksTraversal verifies that volume/snapshot
// names which would escape the engine root (via "../", absolute paths, or
// separators/dots) are rejected by the name validator itself — the error must
// be an invalid-name error, not an incidental IO/not-found failure that would
// also occur if validation were missing.
func TestEngine_NameValidation_BlocksTraversal(t *testing.T) {
	e := NewEngine(t.TempDir())
	bad := []string{
		"",
		"../../etc/cron.d/x",
		"..",
		"../",
		"a/b",
		"/tmp/abs",
		"a.b",
		"a b",
		strings.Repeat("x", 129),
	}
	for _, name := range bad {
		t.Run(fmt.Sprintf("name_%q", name), func(t *testing.T) {
			// Each op must fail specifically with an invalid-name error so a
			// missing validator (which would surface as not-found/IO errors)
			// cannot satisfy the assertion.
			if _, err := e.CreateVolume(name, 1<<20); err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("CreateVolume err = %v, want invalid-name error", err)
			}
			if err := e.DeleteVolume(name); err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("DeleteVolume err = %v, want invalid-name error", err)
			}
			if _, err := e.GetVolumeInfo(name); err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("GetVolumeInfo err = %v, want invalid-name error", err)
			}
			if _, err := e.CreateSnapshot(name, "snap"); err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("CreateSnapshot(source) err = %v, want invalid-name error", err)
			}
			if _, err := e.CreateSnapshot("src", name); err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("CreateSnapshot(snapshot) err = %v, want invalid-name error", err)
			}
			if err := e.DeleteSnapshot(name); err == nil || !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("DeleteSnapshot err = %v, want invalid-name error", err)
			}
			// ListSnapshots("") is a valid "list all" filter, so only non-empty
			// names must be rejected there.
			if name != "" {
				if _, err := e.ListSnapshots(name); err == nil || !strings.Contains(err.Error(), "invalid") {
					t.Fatalf("ListSnapshots err = %v, want invalid-name error", err)
				}
			}
		})
	}
	// Nothing may have been created inside or outside the engine root.
	entries, err := os.ReadDir(e.root)
	if err != nil {
		t.Fatalf("readdir root: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, ent := range entries {
			names = append(names, ent.Name())
		}
		t.Fatalf("traversal attempts created files: %v", names)
	}
}

func TestEngine_VolumeSnapshotLifecycle(t *testing.T) {
	t.Run("volume snapshot basics", func(t *testing.T) {
		root := t.TempDir()
		e := NewEngine(root)

		path, err := e.CreateVolume("data", 1<<20)
		if err != nil {
			t.Fatalf("create volume: %v", err)
		}
		if filepath.Dir(path) != root {
			t.Fatalf("volume created outside engine root: %s", path)
		}

		info, err := e.GetVolumeInfo("data")
		if err != nil {
			t.Fatalf("volume info: %v", err)
		}
		if info.SizeBytes != 1<<20 {
			t.Fatalf("volume size = %d, want %d", info.SizeBytes, uint64(1<<20))
		}
		if info.CreatedAt == "" {
			t.Fatalf("CreatedAt empty")
		}

		vols, err := e.ListVolumes()
		if err != nil || len(vols) != 1 || vols[0].Name != "data" {
			t.Fatalf("list volumes: err=%v len=%d", err, len(vols))
		}

		snapPath, err := e.CreateSnapshot("data", "s1")
		if err != nil {
			t.Fatalf("create snapshot: %v", err)
		}
		if filepath.Dir(snapPath) != root {
			t.Fatalf("snapshot created outside engine root: %s", snapPath)
		}

		snaps, err := e.ListSnapshots("data")
		if err != nil || len(snaps) != 1 {
			t.Fatalf("list snapshots(data): err=%v len=%d", err, len(snaps))
		}
		if snaps[0].Name != "s1" || snaps[0].OriginVolume != "data" {
			t.Fatalf("snapshot record mismatch: %+v", snaps[0])
		}
		// empty filter lists all snapshots
		all, err := e.ListSnapshots("")
		if err != nil || len(all) != 1 {
			t.Fatalf("list snapshots(all): err=%v len=%d", err, len(all))
		}

		if err := e.DeleteSnapshot("s1"); err != nil {
			t.Fatalf("delete snapshot: %v", err)
		}
		if err := e.DeleteVolume("data"); err != nil {
			t.Fatalf("delete volume: %v", err)
		}
		vols2, err := e.ListVolumes()
		if err != nil || len(vols2) != 0 {
			t.Fatalf("after delete: err=%v len=%d", err, len(vols2))
		}
	})

	// Chained snapshots: vol -> snapA -> snapB. Runs on a separately
	// initialized engine and temp dir so the chain shape under test is
	// exactly two snapshots over one volume, independent of the basics
	// subtest above. Filtering by the root volume must return BOTH snapshots.
	t.Run("chained snapshots resolve to root volume", func(t *testing.T) {
		e := NewEngine(t.TempDir())
		if _, err := e.CreateVolume("data", 1<<20); err != nil {
			t.Fatalf("create volume: %v", err)
		}
		if _, err := e.CreateSnapshot("data", "chain-a"); err != nil {
			t.Fatalf("create chain-a: %v", err)
		}
		if _, err := e.CreateSnapshot("chain-a", "chain-b"); err != nil {
			t.Fatalf("create chain-b (snap of snap): %v", err)
		}
		chain, err := e.ListSnapshots("data")
		if err != nil {
			t.Fatalf("list snapshots(data) after chaining: %v", err)
		}
		got := map[string]string{}
		for _, s := range chain {
			got[s.Name] = s.OriginVolume
		}
		if got["chain-a"] != "data" {
			t.Fatalf("chain-a origin = %q, want data", got["chain-a"])
		}
		if got["chain-b"] != "data" {
			t.Fatalf("chain-b origin = %q, want data (root of chain)", got["chain-b"])
		}
		if len(chain) != 2 {
			t.Fatalf("filtering by root volume returned %d snapshots, want 2: %+v", len(chain), chain)
		}
	})

	// Origin stays empty when the backing-chain walk cannot resolve a root
	// volume. Deleting any link makes the overlay unopenable (openGuestImage
	// validates the chain transitively, so the snapshot is skipped entirely),
	// so the reachable walk failure is the hop limit: a chain DEEPER than the
	// walk's 64-hop bound ends without finding the root volume.
	t.Run("chain deeper than walk limit leaves origin unknown", func(t *testing.T) {
		e := NewEngine(t.TempDir())
		if _, err := e.CreateVolume("data", 1<<20); err != nil {
			t.Fatalf("create volume: %v", err)
		}
		// vol -> s1 -> ... -> s65: s65 needs 65 hops, one past the limit.
		src := "data"
		for i := 1; i <= 65; i++ {
			name := fmt.Sprintf("s%d", i)
			if _, err := e.CreateSnapshot(src, name); err != nil {
				t.Fatalf("create %s: %v", name, err)
			}
			src = name
		}
		all, err := e.ListSnapshots("")
		if err != nil {
			t.Fatalf("list snapshots(all): %v", err)
		}
		byName := map[string]Snapshot{}
		for _, s := range all {
			byName[s.Name] = s
		}
		// s64 resolves within the hop budget; s65 exhausts it.
		if got := byName["s64"]; got.OriginVolume != "data" {
			t.Fatalf("s64 origin = %q, want data", got.OriginVolume)
		}
		s65, ok := byName["s65"]
		if !ok {
			t.Fatalf("s65 missing from listing")
		}
		if s65.OriginVolume != "" {
			t.Fatalf("unresolvable chain must report empty origin, got %q", s65.OriginVolume)
		}
		// An unknown origin must not be claimed by any volume filter.
		filtered, err := e.ListSnapshots("data")
		if err != nil {
			t.Fatalf("list snapshots(data): %v", err)
		}
		for _, s := range filtered {
			if s.Name == "s65" {
				t.Fatalf("s65 with unknown origin must not be claimed by volume filter")
			}
		}
	})
}
