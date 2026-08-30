package network

// registry.go is the persistent network registry (bucket-2 "IPAM 硬编码
// 子网"): `umlctl network create` prefers the historical default
// 10.0.0.0/24 (gateway 10.0.0.1, baked into existing guest images) and
// only draws the next free /24 from the pool when that subnet is taken —
// the configured pool (PVM_NETWORK_POOL, default 10.64.0.0/12), skipping
// subnets that overlap the host's own interfaces, and records the mapping
// durably so a restart never hands the same subnet to two bridges.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"uml-container/internal/fsjson"
)

// DefaultNetworkPool is the private /12 the allocator draws /24s from.
// 10.64.0.0/12 (10.64.0.0–10.79.255.255) avoids the historical default
// bridge (10.0.0.0/24) and the most common LAN ranges.
const DefaultNetworkPool = "10.64.0.0/12"

// NetworkRecord is one registered bridge network.
type NetworkRecord struct {
	Name      string    `json:"name"`
	Subnet    string    `json:"subnet"` // gateway CIDR, e.g. 10.64.7.1/24
	CreatedAt time.Time `json:"created_at"`
}

// NetworkRegistry persists name -> subnet assignments.
type NetworkRegistry struct {
	path string
	mu   chan struct{} // semaphore-style lock (kept off the hot IPAM path)
	nets map[string]NetworkRecord
}

// LoadNetworkRegistry opens (or creates) the registry under stateRoot.
func LoadNetworkRegistry(stateRoot string) (*NetworkRegistry, error) {
	if stateRoot == "" {
		stateRoot = "/var/lib/uml-container"
	}
	path := filepath.Join(stateRoot, "networks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("network registry: %w", err)
	}
	r := &NetworkRegistry{path: path, mu: make(chan struct{}, 1), nets: map[string]NetworkRecord{}}
	r.mu <- struct{}{}
	<-r.mu
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		var dump struct {
			Networks []NetworkRecord `json:"networks"`
		}
		if jerr := json.Unmarshal(raw, &dump); jerr != nil {
			_ = os.Rename(path, path+".corrupt")
		} else {
			for _, n := range dump.Networks {
				r.nets[n.Name] = n
			}
		}
	}
	return r, nil
}

func (r *NetworkRegistry) persistLocked() {
	dump := struct {
		Networks []NetworkRecord `json:"networks"`
	}{}
	names := make([]string, 0, len(r.nets))
	for n := range r.nets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		dump.Networks = append(dump.Networks, r.nets[n])
	}
	_ = fsjson.Write(r.path, dump)
}

// lockFile takes an exclusive inter-process flock on <path>.lock. The
// in-process mu alone cannot stop two `umlctl network create` processes
// from loading the same state, drawing the same /24 and overwriting each
// other's records — mutation paths hold BOTH locks and re-read the file
// inside the flock (see withFlock).
func (r *NetworkRegistry) lockFile() (*os.File, error) {
	f, err := os.OpenFile(r.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("network registry: lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("network registry: flock: %w", err)
	}
	return f, nil
}

// withFlock runs fn under the inter-process lock (caller already holds the
// in-process mu). Closing the lock file releases the flock.
func (r *NetworkRegistry) withFlock(fn func() (string, error)) (string, error) {
	lf, err := r.lockFile()
	if err != nil {
		return "", err
	}
	defer lf.Close()
	// Another process may have persisted changes since THIS process loaded
	// the registry — rebuild memory state from the file before mutating.
	r.reloadLocked()
	return fn()
}

// reloadLocked replaces in-memory records with the file's contents. Empty
// or missing files leave the map empty (fresh registry).
func (r *NetworkRegistry) reloadLocked() {
	r.nets = map[string]NetworkRecord{}
	raw, err := os.ReadFile(r.path)
	if err != nil || len(raw) == 0 {
		return
	}
	var dump struct {
		Networks []NetworkRecord `json:"networks"`
	}
	if json.Unmarshal(raw, &dump) == nil {
		for _, n := range dump.Networks {
			r.nets[n.Name] = n
		}
	}
}

// Allocate reserves the next free /24 for name and returns its gateway CIDR
// (the .1 address). Idempotent: an existing name returns its recorded subnet.
func (r *NetworkRegistry) Allocate(name string) (string, error) {
	r.mu <- struct{}{}
	defer func() { <-r.mu }()
	return r.withFlock(func() (string, error) { return r.allocateLocked(name) })
}

// AllocatePreferred reserves want for name when it is free (or already
// recorded under the same name); when want is nil, or another registered
// network or the host already occupies it, allocation falls back to the
// pool scan exactly like Allocate. This keeps the historical default
// (10.0.0.0/24, gateway 10.0.0.1 — baked into existing guest images and
// test fixtures) stable for the first bridge, while still preventing
// collisions across multiple bridges.
func (r *NetworkRegistry) AllocatePreferred(name string, want *net.IPNet) (string, error) {
	r.mu <- struct{}{}
	defer func() { <-r.mu }()
	return r.withFlock(func() (string, error) {
		if rec, ok := r.nets[name]; ok {
			return rec.Subnet, nil
		}
		if want != nil {
			free := true
			for _, t := range r.takenSubnetsLocked() {
				if t.Contains(want.IP) || want.Contains(t.IP) {
					free = false
					break
				}
			}
			if free {
				gw := make(net.IP, 4)
				copy(gw, want.IP.To4())
				gw[3] = 1
				gwCIDR := fmt.Sprintf("%s/24", gw)
				r.nets[name] = NetworkRecord{Name: name, Subnet: gwCIDR, CreatedAt: time.Now().UTC()}
				r.persistLocked()
				return gwCIDR, nil
			}
		}
		return r.allocateLocked(name)
	})
}

func (r *NetworkRegistry) allocateLocked(name string) (string, error) {
	if rec, ok := r.nets[name]; ok {
		return rec.Subnet, nil
	}
	pool := os.Getenv("PVM_NETWORK_POOL")
	if pool == "" {
		pool = DefaultNetworkPool
	}
	_, poolNet, err := net.ParseCIDR(pool)
	if err != nil {
		return "", fmt.Errorf("network registry: bad PVM_NETWORK_POOL %q: %w", pool, err)
	}
	taken := r.takenSubnetsLocked()
	next, err := nextFree24(poolNet, taken)
	if err != nil {
		return "", err
	}
	gw := make(net.IP, 4)
	copy(gw, next.IP.To4())
	gw[3] = 1
	gwCIDR := fmt.Sprintf("%s/24", gw)
	r.nets[name] = NetworkRecord{Name: name, Subnet: gwCIDR, CreatedAt: time.Now().UTC()}
	r.persistLocked()
	return gwCIDR, nil
}

// takenSubnetsLocked unions registered subnets with the host's interface
// subnets so a fresh /24 never collides with the machine's own networks.
func (r *NetworkRegistry) takenSubnetsLocked() []*net.IPNet {
	var nets []*net.IPNet
	for _, rec := range r.nets {
		if _, n, err := net.ParseCIDR(rec.Subnet); err == nil {
			nets = append(nets, n)
		}
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			addrs, aerr := ifc.Addrs()
			if aerr != nil {
				continue
			}
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if v4 := ipn.IP.To4(); v4 != nil {
						// Treat every host address as occupying its whole /24:
						// bridge subnets must not share space with host nets.
						mask := net.CIDRMask(24, 32)
						nets = append(nets, &net.IPNet{IP: v4.Mask(mask), Mask: mask})
					}
				}
			}
		}
	}
	return nets
}

// nextFree24 scans pool in /24 steps for the first subnet none of taken
// covers.
func nextFree24(pool *net.IPNet, taken []*net.IPNet) (*net.IPNet, error) {
	base := pool.IP.To4()
	if base == nil {
		return nil, fmt.Errorf("network registry: pool must be IPv4")
	}
	ones, _ := pool.Mask.Size()
	if ones > 24 {
		return nil, fmt.Errorf("network registry: pool /%d smaller than /24", ones)
	}
	start := binaryOrder(base)
	end := start | (1<<(32-ones) - 1)
	for cur := start; cur <= end-255; cur += 256 {
		candidate := &net.IPNet{IP: orderBinary(cur), Mask: net.CIDRMask(24, 32)}
		free := true
		for _, t := range taken {
			if t.Contains(candidate.IP) || candidate.Contains(t.IP) {
				free = false
				break
			}
		}
		if free {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("network registry: pool exhausted (all /24s taken)")
}

func binaryOrder(ip net.IP) uint32 {
	b := ip.To4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func orderBinary(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Release forgets name's reservation.
func (r *NetworkRegistry) Release(name string) {
	r.mu <- struct{}{}
	_, _ = r.withFlock(func() (string, error) {
		delete(r.nets, name)
		r.persistLocked()
		return "", nil
	})
	<-r.mu
}

// Get returns name's record.
func (r *NetworkRegistry) Get(name string) (NetworkRecord, bool) {
	r.mu <- struct{}{}
	rec, ok := r.nets[name]
	<-r.mu
	return rec, ok
}

// List returns every record sorted by name.
func (r *NetworkRegistry) List() []NetworkRecord {
	r.mu <- struct{}{}
	out := make([]NetworkRecord, 0, len(r.nets))
	for _, rec := range r.nets {
		out = append(out, rec)
	}
	<-r.mu
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
