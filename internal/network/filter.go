package network

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Per-tap whitelist-map registry. Replacing the former package-global
// *ebpf.Map: the global was overwritten without synchronization on every
// AttachEgressFilter call (racing writers), leaked the previous map's fd,
// and let one container's policy updates land in another container's map.
// The registry keys maps by tap name so each container owns its own map.
var (
	whitelistMu   sync.Mutex
	whitelistMaps = map[string]*ebpf.Map{}
)

// WhitelistMapFor returns the eBPF whitelist map registered for tapName, or
// nil when no egress filter is attached to it.
func WhitelistMapFor(tapName string) *ebpf.Map {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	return whitelistMaps[tapName]
}

// registerWhitelistMap stores m under tapName, closing and dropping any map
// previously registered for the same tap (re-attach replaces the filter).
func registerWhitelistMap(tapName string, m *ebpf.Map) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	if old := whitelistMaps[tapName]; old != nil && old != m {
		old.Close()
	}
	whitelistMaps[tapName] = m
}

// unregisterWhitelistMap drops (and closes) the map for tapName if it is
// still the one registered.
func unregisterWhitelistMap(tapName string, m *ebpf.Map) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	if cur := whitelistMaps[tapName]; cur == m {
		m.Close()
		delete(whitelistMaps, tapName)
	}
}

// AttachEgressFilter loads the egress BPF program, attaches it to tapName's
// egress clsact classifier and registers the program's whitelist map for
// that tap. It returns the map so callers can update policy without going
// through a shared global. On error every loaded resource is closed.
func AttachEgressFilter(tapName string) (*ebpf.Map, error) {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}
	// From here on objs.Close() releases both the program and the map on
	// every failure path; the success path hands ownership of
	// objs.WhitelistMap to the registry and only closes the program fd.
	success := false
	defer func() {
		if !success {
			objs.Close()
		}
	}()

	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return nil, fmt.Errorf("failed to get link %s: %w", tapName, err)
	}

	// Add clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("failed to add clsact qdisc: %w", err)
	}

	// Attach filter to egress
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.EgressFilter.FD(),
		Name:         "egress_filter",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		if errors.Is(err, unix.EEXIST) {
			if err := netlink.FilterReplace(filter); err != nil {
				return nil, fmt.Errorf("failed to replace BPF filter: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to attach BPF filter: %w", err)
		}
	}

	// Register this container's map under its own tap; a duplicate attach
	// closes the stale map instead of leaking its fd. Ownership of the map
	// moves to the registry (the deferred objs.Close is skipped on success).
	m := objs.WhitelistMap
	registerWhitelistMap(tapName, m)

	// Close the program fd; the map now belongs to the registry.
	objs.EgressFilter.Close()
	success = true
	return m, nil
}

// DetachEgressFilter unregisters (and closes) the whitelist map previously
// registered for tapName. Safe to call when nothing is attached.
func DetachEgressFilter(tapName string) {
	if m := WhitelistMapFor(tapName); m != nil {
		unregisterWhitelistMap(tapName, m)
	}
}
