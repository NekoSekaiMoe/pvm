package network

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryAllocatesDistinctSubnets(t *testing.T) {
	dir := t.TempDir()
	r, err := LoadNetworkRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range []string{"net-a", "net-b", "net-c"} {
		gw, err := r.Allocate(name)
		if err != nil {
			t.Fatal(err)
		}
		if seen[gw] {
			t.Fatalf("duplicate subnet %s", gw)
		}
		seen[gw] = true
		_, ipn, err := net.ParseCIDR(gw)
		host := gw
		if i := strings.IndexByte(gw, '/'); i >= 0 {
			host = gw[:i]
		}
		if err != nil || !ipn.Contains(net.ParseIP(host)) {
			t.Fatalf("bad gateway cidr %s", gw)
		}
	}

	// Persistence: a fresh registry keeps the assignments and hands out a
	// NEW subnet for a new name.
	r2, _ := LoadNetworkRegistry(dir)
	if _, ok := r2.Get("net-a"); !ok {
		t.Fatal("assignment must persist")
	}
	again, _ := r2.Allocate("net-a")
	if !seen[again] {
		t.Fatalf("idempotent allocate must return the recorded subnet, got %s", again)
	}
	fresh, _ := r2.Allocate("net-z")
	if seen[fresh] {
		t.Fatalf("fresh name must get a fresh subnet, got %s", fresh)
	}

	// Release frees the name.
	r2.Release("net-a")
	if _, ok := r2.Get("net-a"); ok {
		t.Fatal("release must forget the name")
	}
}

func TestRegistrySkipsHostSubnets(t *testing.T) {
	r, err := LoadNetworkRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gw, err := r.Allocate("x")
	if err != nil {
		t.Fatal(err)
	}
	_, ipn, _ := net.ParseCIDR(gw)
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if v4 := ipnet.IP.To4(); v4 != nil && ipn.Contains(v4) {
						t.Fatalf("allocated %s overlaps host addr %s", gw, v4)
					}
				}
			}
		}
	}
}

func TestRegistryCustomPool(t *testing.T) {
	t.Setenv("PVM_NETWORK_POOL", "192.168.200.0/24")
	r, _ := LoadNetworkRegistry(t.TempDir())
	gw, err := r.Allocate("custom")
	if err != nil {
		t.Fatal(err)
	}
	gwHost := gw
	if i := strings.IndexByte(gw, '/'); i >= 0 {
		gwHost = gw[:i]
	}
	if !net.ParseIP(gwHost).Equal(net.ParseIP("192.168.200.1")) {
		t.Fatalf("custom pool first allocation = %s, want 192.168.200.1", gw)
	}
}

// A store path occupied by a directory makes every fsjson.Write fail at
// the atomic rename step (rename file -> dir = EISDIR) while loads still
// succeed — a deterministic, root-safe way to exercise persist-failure
// rollback without chmod tricks.
func TestRegistryAllocateRollsBackWhenPersistFails(t *testing.T) {
	stateRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(stateRoot, "networks.json"), 0o700); err != nil {
		t.Fatalf("plant broken store: %v", err)
	}
	r, err := LoadNetworkRegistry(stateRoot)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := r.Allocate("br0"); err == nil {
		t.Fatal("Allocate must fail when the reservation cannot be persisted")
	}
	if _, ok := r.Get("br0"); ok {
		t.Fatal("failed Allocate left a record in memory (rollback missing)")
	}

	_, want, cerr := net.ParseCIDR("10.9.9.0/24")
	if cerr != nil {
		t.Fatalf("cidr: %v", cerr)
	}
	if _, err := r.AllocatePreferred("br1", want); err == nil {
		t.Fatal("AllocatePreferred must fail when the preferred reservation cannot be persisted")
	}
	if _, ok := r.Get("br1"); ok {
		t.Fatal("failed AllocatePreferred left a record in memory (rollback missing)")
	}
}

// A >248-byte base name keeps the store file readable (the record below is
// planted on disk) while fsjson's temp-file pattern ("." + base + "-*.tmp"
// plus a random suffix) always exceeds the 255-byte NAME_MAX — reads
// succeed and every write fails. That is the state Release's rollback
// needs: the directory trick above would wipe memory during withFlock's
// reload before Release could restore the record.
func TestRegistryReleaseRollsBackWhenPersistFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), strings.Repeat("n", 250))
	body := `{"networks":[{"name":"br0","subnet":"10.0.0.1/24","created_at":"2024-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("plant store: %v", err)
	}
	r := &NetworkRegistry{path: path, mu: make(chan struct{}, 1), nets: map[string]NetworkRecord{}}
	if err := r.Release("br0"); err == nil {
		t.Fatal("Release must fail when the deletion cannot be persisted")
	}
	rec, ok := r.Get("br0")
	if !ok {
		t.Fatal("failed Release dropped the reservation (rollback missing)")
	}
	if rec.Subnet != "10.0.0.1/24" {
		t.Fatalf("restored record = %+v, want subnet 10.0.0.1/24", rec)
	}
}

// TestRegistryReloadFailureAbortsMutation: a registry file that exists but
// cannot be parsed must ABORT Allocate/Release instead of proceeding with
// cleared in-memory state — persistLocked would otherwise overwrite the
// (unreadable but valid) registry with an empty one and the same /24 could
// be allocated to two bridges after a restart.
func TestRegistryReloadFailureAbortsMutation(t *testing.T) {
	stateRoot := t.TempDir()
	r, err := LoadNetworkRegistry(stateRoot)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := r.Allocate("br0"); err != nil {
		t.Fatalf("healthy Allocate: %v", err)
	}
	storePath := filepath.Join(stateRoot, "networks.json")
	corrupt := []byte("{definitely not json")
	if err := os.WriteFile(storePath, corrupt, 0o600); err != nil {
		t.Fatalf("plant corrupt store: %v", err)
	}

	if _, err := r.Allocate("br1"); err == nil {
		t.Fatal("Allocate must fail when the registry cannot be reloaded")
	}
	if _, ok := r.Get("br1"); ok {
		t.Fatal("Allocate ran its callback despite the failed reload")
	}
	if err := r.Release("br0"); err == nil {
		t.Fatal("Release must fail when the registry cannot be reloaded")
	}
	if _, ok := r.Get("br0"); !ok {
		t.Fatal("Release dropped a record despite the failed reload")
	}
	// The corrupt file must be intact, not overwritten with empty state.
	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if string(raw) != string(corrupt) {
		t.Fatalf("corrupt registry was overwritten: %q", raw)
	}
}
