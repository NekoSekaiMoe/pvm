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
//
// Maps handed out by WhitelistMapFor are reference-counted: a re-attach
// that replaces a registered map must not close it while callers still
// hold it. The replaced map is retired and closed only once its last
// outstanding reference is released (ReleaseWhitelistMap).
var (
	whitelistMu sync.Mutex
	// whitelistTaps holds the current registration for each tap.
	whitelistTaps = map[string]*whitelistEntry{}
	// whitelistRetired holds replaced/unregistered entries that still have
	// outstanding references; each is closed once its refcount drains.
	whitelistRetired = map[string][]*whitelistEntry{}
)

// whitelistEntry is one registered (or retired) map plus the number of
// references handed out via WhitelistMapFor that have not been released.
type whitelistEntry struct {
	m    *ebpf.Map
	refs int
	dead bool // replaced or unregistered; close as soon as refs drains
}

// WhitelistMapFor returns the eBPF whitelist map registered for tapName, or
// nil when no egress filter is attached to it. The returned map is kept
// alive until the caller releases it with ReleaseWhitelistMap: a concurrent
// re-attach replaces the registration but defers closing the old map until
// every outstanding reference is gone.
func WhitelistMapFor(tapName string) *ebpf.Map {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	e := whitelistTaps[tapName]
	if e == nil {
		return nil
	}
	e.refs++
	return e.m
}

// ReleaseWhitelistMap drops one reference previously taken via
// WhitelistMapFor. When the map was replaced or unregistered in the
// meantime and this was the last outstanding reference, the map is closed
// here. Releasing a map that is not (or no longer) registered for tapName,
// or that has no outstanding references, is a no-op.
func ReleaseWhitelistMap(tapName string, m *ebpf.Map) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	e := entryForLocked(tapName, m)
	if e == nil || e.refs <= 0 {
		return
	}
	e.refs--
	if e.dead && e.refs == 0 {
		closeRetiredLocked(tapName, e)
	}
}

// entryForLocked finds the live-or-retired entry holding m. Caller holds
// whitelistMu.
func entryForLocked(tapName string, m *ebpf.Map) *whitelistEntry {
	if e := whitelistTaps[tapName]; e != nil && e.m == m {
		return e
	}
	for _, e := range whitelistRetired[tapName] {
		if e.m == m {
			return e
		}
	}
	return nil
}

// retireLocked marks e dead: closed immediately when no caller still holds
// a reference, otherwise parked on the retired list until its last
// reference is released. Caller holds whitelistMu.
func retireLocked(tapName string, e *whitelistEntry) {
	e.dead = true
	if e.refs > 0 {
		whitelistRetired[tapName] = append(whitelistRetired[tapName], e)
		return
	}
	e.m.Close()
}

// closeRetiredLocked removes a drained retired entry from the retired list
// and closes its map. Caller holds whitelistMu.
func closeRetiredLocked(tapName string, e *whitelistEntry) {
	for i, r := range whitelistRetired[tapName] {
		if r == e {
			retired := whitelistRetired[tapName]
			whitelistRetired[tapName] = append(retired[:i], retired[i+1:]...)
			break
		}
	}
	e.m.Close()
}

// registerWhitelistMap stores m under tapName (re-attach replaces the
// filter). The previously registered map is retired: closed right away
// when nobody references it, otherwise kept alive until its references
// drain — callers may still hold it via WhitelistMapFor.
func registerWhitelistMap(tapName string, m *ebpf.Map) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	if old := whitelistTaps[tapName]; old != nil {
		if old.m == m {
			return // same map re-registered: keep the entry (and its refs)
		}
		retireLocked(tapName, old)
	}
	whitelistTaps[tapName] = &whitelistEntry{m: m}
}

// unregisterWhitelistMap drops (and closes, once unreferenced) the map for
// tapName if it is still the one registered.
func unregisterWhitelistMap(tapName string, m *ebpf.Map) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	if e := whitelistTaps[tapName]; e != nil && e.m == m {
		retireLocked(tapName, e)
		delete(whitelistTaps, tapName)
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

// UnregisterWhitelistMap unregisters (and closes, once unreferenced) the
// whitelist map previously registered for tapName. Safe to call when
// nothing is attached.
//
// It deliberately does NOT touch the egress tc filter or the clsact qdisc:
// the filter is installed via tc by LoadEgressFilter (internal/ebpf), which
// does not record whether IT created the clsact qdisc — removing a qdisc our
// caller did not own would break unrelated filters on the same device. The
// operator tears the whole device down with the TAP anyway.
func UnregisterWhitelistMap(tapName string) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	if e := whitelistTaps[tapName]; e != nil {
		retireLocked(tapName, e)
		delete(whitelistTaps, tapName)
	}
}
