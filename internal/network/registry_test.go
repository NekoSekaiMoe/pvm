package network

import (
	"net"
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
