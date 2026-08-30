package network

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
