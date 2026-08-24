package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// DefaultBridgeCIDR is the bridge subnet used when NetworkSpec.GatewayIP is
// empty. It matches the historical hardcoded default of SetupBridge
// (10.0.0.1/24) so a spec that sets no gateway gets the same data plane.
const DefaultBridgeCIDR = "10.0.0.1/24"

// guestIPStartHost is the first host offset tried for auto-allocated guest
// IPs: the low end of the subnet stays free for the gateway (.1) and any
// operator-managed addresses, guests start at .100.
const guestIPStartHost = 100

// IPAM is a minimal in-memory guest-IP allocator for one bridge subnet.
// The host never DHCPs and the guest self-assigns the address it is handed
// via the pvm_ip= kernel parameter, so this allocator is the single source
// of truth that keeps two tasks from picking the same address. It is
// in-memory on purpose: the addresses are meaningful only while their tasks
// run, and a manager restart frees every tap (and its filter) anyway.
type IPAM struct {
	mu      sync.Mutex
	subnet  *net.IPNet // canonical network (host bits cleared)
	gateway uint32     // host-order gateway address
	base    uint32     // host-order network address
	bcast   uint32     // host-order broadcast address
	byTask  map[string]uint32
	taken   map[uint32]string
}

// NewIPAM parses gatewayCIDR (host address + prefix, e.g. "10.0.0.1/24")
// and returns an allocator for that subnet. An empty gatewayCIDR selects
// DefaultBridgeCIDR. IPv4 only — the guest contract (pvm_ip=) and the BPF
// whitelist map are both IPv4.
func NewIPAM(gatewayCIDR string) (*IPAM, error) {
	if gatewayCIDR == "" {
		gatewayCIDR = DefaultBridgeCIDR
	}
	gwIP, ipnet, err := net.ParseCIDR(gatewayCIDR)
	if err != nil {
		return nil, fmt.Errorf("network: invalid gateway CIDR %q: %w", gatewayCIDR, err)
	}
	gw4 := gwIP.To4()
	if gw4 == nil {
		return nil, fmt.Errorf("network: gateway CIDR %q is not IPv4", gatewayCIDR)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones < 8 || ones > 30 {
		return nil, fmt.Errorf("network: gateway CIDR %q needs an IPv4 prefix of /8../30", gatewayCIDR)
	}
	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	mask := ^uint32(0) << (32 - ones)
	return &IPAM{
		subnet:  ipnet,
		gateway: binary.BigEndian.Uint32(gw4),
		base:    base,
		bcast:   base | ^mask,
		byTask:  map[string]uint32{},
		taken:   map[uint32]string{},
	}, nil
}

// SharedIPAM returns the process-wide IPAM for the given gateway CIDR,
// creating it on first use. All tasks on one bridge subnet MUST allocate
// from the same instance or the collision guarantee is void; keying the
// registry by the canonical subnet keeps specs that spell the same subnet
// differently ("10.0.0.1/24" vs the default) on one allocator.
var (
	sharedIPAMMu sync.Mutex
	sharedIPAMs  = map[string]*IPAM{}
)

func SharedIPAM(gatewayCIDR string) (*IPAM, error) {
	a, err := NewIPAM(gatewayCIDR)
	if err != nil {
		return nil, err
	}
	key := a.subnet.String()
	sharedIPAMMu.Lock()
	defer sharedIPAMMu.Unlock()
	if existing, ok := sharedIPAMs[key]; ok {
		return existing, nil
	}
	sharedIPAMs[key] = a
	return a, nil
}

// GatewayIP returns the gateway (host-side bridge) address of the subnet.
func (a *IPAM) GatewayIP() net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], a.gateway)
	return net.IP(b[:])
}

// Allocate reserves the next free guest IP for taskID: host offset .100 and
// up, skipping the gateway, the network/broadcast addresses and every
// address already taken. Re-allocating for the same taskID returns its
// existing address (idempotent for retried launches).
func (a *IPAM) Allocate(taskID string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cur, ok := a.byTask[taskID]; ok {
		return u32ToIP(cur), nil
	}
	for host := a.base + guestIPStartHost; host < a.bcast; host++ {
		if host == a.gateway {
			continue
		}
		if _, used := a.taken[host]; used {
			continue
		}
		a.taken[host] = taskID
		a.byTask[taskID] = host
		return u32ToIP(host), nil
	}
	return nil, fmt.Errorf("network: guest IP pool exhausted in %s (from offset .%d)", a.subnet, guestIPStartHost)
}

// AllocateGuest reserves an operator-pinned guest IP (NetworkSpec.GuestIP)
// for taskID. The address must be IPv4, lie inside the subnet, and be
// neither the gateway nor an address another task already holds.
func (a *IPAM) AllocateGuest(taskID, guestIP string) (net.IP, error) {
	ip := net.ParseIP(guestIP)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("network: guest_ip %q is not a valid IPv4 address", guestIP)
	}
	host := binary.BigEndian.Uint32(ip.To4())
	if !a.subnet.Contains(ip) {
		return nil, fmt.Errorf("network: guest_ip %q is outside the bridge subnet %s", guestIP, a.subnet)
	}
	if host == a.gateway {
		return nil, fmt.Errorf("network: guest_ip %q collides with the gateway address", guestIP)
	}
	if host == a.base || host == a.bcast {
		return nil, fmt.Errorf("network: guest_ip %q is the network/broadcast address of %s", guestIP, a.subnet)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cur, ok := a.byTask[taskID]; ok {
		if cur == host {
			return u32ToIP(cur), nil
		}
		return nil, fmt.Errorf("network: task %s already holds %s, cannot switch to %s", taskID, u32ToIP(cur), guestIP)
	}
	if owner, used := a.taken[host]; used {
		return nil, fmt.Errorf("network: guest_ip %q is already allocated to task %s", guestIP, owner)
	}
	a.taken[host] = taskID
	a.byTask[taskID] = host
	return u32ToIP(host), nil
}

// Release frees the address held by taskID (if any). Safe to call when the
// task never allocated.
func (a *IPAM) Release(taskID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cur, ok := a.byTask[taskID]; ok {
		delete(a.byTask, taskID)
		delete(a.taken, cur)
	}
}

// u32ToIP renders a host-order IPv4 integer as a net.IP.
func u32ToIP(v uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:])
}
