package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// bpfPinRoot is the bpffs directory under which each task's whitelist map is
// pinned: /sys/fs/bpf/pvm/<taskID>/whitelist_map. Pinning is userspace-
// controlled (the map deliberately carries no LIBBPF_PIN_BY_NAME) so every
// task owns an independent whitelist instead of sharing one global map.
const bpfPinRoot = "/sys/fs/bpf/pvm"

// taskPinIDRe guards the task id before it is joined into a bpffs path.
// It matches the container package's task-id contract (^[a-zA-Z0-9_-]+$):
// no slashes, no dots, no traversal possible.
var taskPinIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// EgressFilterError wraps every failure of the per-task TC egress filter
// attach/detach path. Op names the failing step (load, rewrite, qdisc,
// filter, pin, ...). The manager treats ANY attach failure as degraded mode
// (audit security:degraded_warning and continue, L7 proxy still enforces);
// the typed error lets callers distinguish an environment gap (no root, no
// bpffs, kernel without clsact) from a programming bug.
type EgressFilterError struct {
	Op  string
	Tap string
	Err error
}

func (e *EgressFilterError) Error() string {
	return fmt.Sprintf("network: tc egress filter %s on %s: %v", e.Op, e.Tap, e.Err)
}
func (e *EgressFilterError) Unwrap() error { return e.Err }

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

// WhitelistPinPath returns the bpffs pin path of taskID's whitelist map.
// taskID must match ^[a-zA-Z0-9_-]+$ (the same contract StartTask enforces)
// so the id can never escape bpfPinRoot.
func WhitelistPinPath(taskID string) (string, error) {
	if !taskPinIDRe.MatchString(taskID) {
		return "", fmt.Errorf("network: invalid task id %q for bpf pin path", taskID)
	}
	return filepath.Join(bpfPinRoot, taskID, "whitelist_map"), nil
}

// whitelistPinDir returns the per-task pin directory (parent of
// WhitelistPinPath). Same taskID contract as WhitelistPinPath.
func whitelistPinDir(taskID string) (string, error) {
	if !taskPinIDRe.MatchString(taskID) {
		return "", fmt.Errorf("network: invalid task id %q for bpf pin dir", taskID)
	}
	return filepath.Join(bpfPinRoot, taskID), nil
}

// bpfIPv4 renders an IPv4 address as the raw __u32 the BPF program sees in
// ip->daddr: the four network-order bytes interpreted in host byte order
// (the constants exempt_ip_a/b are compared against ip->daddr directly).
// A nil or non-IPv4 input yields 0, which the program treats as "unset".
func bpfIPv4(ip net.IP) uint32 {
	b := ip.To4()
	if b == nil {
		return 0
	}
	return binary.NativeEndian.Uint32(b)
}

// AttachEgressFilter loads the egress BPF program for ONE task, rewrites
// its SSRF-floor exemptions to the task's gateway and guest IPs, pins the
// whitelist map at /sys/fs/bpf/pvm/<taskID>/whitelist_map, attaches the
// program to tapName's egress clsact classifier and registers the map in
// the per-tap registry. It returns the map so callers can update policy
// without going through a shared global. On error every loaded resource
// (program, map, pin) is released.
//
// Failures come back as *EgressFilterError: no root/CAP_BPF, an unmounted
// bpffs and a kernel without clsact all surface the same way — the caller
// (StartTask) degrades with an audit warning instead of failing the task,
// because the L7 egress proxy remains the enforcement point and this BPF
// floor is defense in depth.
func AttachEgressFilter(tapName, taskID string, gatewayIP, guestIP net.IP) (*ebpf.Map, error) {
	fail := func(op string, err error) (*ebpf.Map, error) {
		return nil, &EgressFilterError{Op: op, Tap: tapName, Err: err}
	}
	pinDir, err := whitelistPinDir(taskID)
	if err != nil {
		return fail("validate", err)
	}
	pinPath, err := WhitelistPinPath(taskID)
	if err != nil {
		return fail("validate", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return fail("load", err)
	}
	// Per-task exemptions: the gateway (default route / proxy target) and the
	// guest's own address pass the RFC1918 SSRF floor; everything else keeps
	// the compiled-in policy. 0 (unset) disables a slot.
	if err := spec.RewriteConstants(map[string]interface{}{
		"exempt_ip_a": bpfIPv4(gatewayIP),
		"exempt_ip_b": bpfIPv4(guestIP),
	}); err != nil {
		return fail("rewrite", err)
	}
	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fail("load", err)
	}
	// From here on objs.Close() releases both the program and the map on
	// every failure path; the success path hands ownership of
	// objs.WhitelistMap to the registry and only closes the program fd.
	success := false
	pinned := false
	defer func() {
		if !success {
			if pinned {
				_ = os.Remove(pinPath)
				_ = os.Remove(pinDir)
			}
			objs.Close()
		}
	}()

	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fail("link", fmt.Errorf("failed to get link %s: %w", tapName, err))
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
		return fail("qdisc", fmt.Errorf("failed to add clsact qdisc: %w", err))
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
				return fail("filter", fmt.Errorf("failed to replace BPF filter: %w", err))
			}
		} else {
			return fail("filter", fmt.Errorf("failed to attach BPF filter: %w", err))
		}
	}

	// Pin the map under the task's own bpffs dir (created here). A missing
	// or read-only bpffs (no root, no mount) fails here with a typed error
	// AFTER the filter is already attached — detach it again so a degraded
	// task never runs with a filter whose map nobody can reach.
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		delBpfFilter(tapName)
		return fail("pin", fmt.Errorf("create pin dir %s: %w", pinDir, err))
	}
	if err := objs.WhitelistMap.Pin(pinPath); err != nil {
		delBpfFilter(tapName)
		_ = os.Remove(pinDir)
		return fail("pin", err)
	}
	pinned = true

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

// delBpfFilter removes the egress BPF filter AttachEgressFilter installed
// on tapName (clsact egress, handle 1). Best-effort: a vanished tap or a
// filter someone else replaced is not an error worth surfacing.
func delBpfFilter(tapName string) {
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return
	}
	_ = netlink.FilterDel(&netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
	})
}

// benignDetachErr reports whether a pin-cleanup failure can be ignored for
// idempotent detach semantics: the target never existed, or this (likely
// unprivileged) process cannot even probe the bpffs tree — nothing it could
// clean up there is reachable for it anyway. Stale pins owned by dead root
// processes are documented cleanup-by-operator leftovers.
func benignDetachErr(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) ||
		errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
}

// DetachTaskFilter is the symmetric teardown of AttachEgressFilter: it
// removes the tc filter from the tap, unregisters (and closes, once
// unreferenced) the per-tap whitelist map, and removes the task's pinned
// map plus its pin directory. Best-effort and idempotent — individual
// failures are joined into the returned error but never stop the remaining
// cleanup steps, so a half-attached task still tears down what it can.
// Safe to call when nothing is attached.
//
// The clsact qdisc is deliberately left in place: the TAP device is torn
// down with the task anyway, and removing a shared qdisc could break
// unrelated filters on the same device.
func DetachTaskFilter(taskID, tapName string) error {
	var errs []error
	if tapName != "" {
		delBpfFilter(tapName)
		UnregisterWhitelistMap(tapName)
	}
	if pinPath, err := WhitelistPinPath(taskID); err == nil {
		if err := os.Remove(pinPath); err != nil && !benignDetachErr(err) {
			errs = append(errs, fmt.Errorf("unpin %s: %w", pinPath, err))
		}
	}
	if pinDir, err := whitelistPinDir(taskID); err == nil {
		if err := os.Remove(pinDir); err != nil && !benignDetachErr(err) {
			errs = append(errs, fmt.Errorf("remove pin dir %s: %w", pinDir, err))
		}
	}
	return errors.Join(errs...)
}

// AddWhitelistEntry inserts ip (an allowlisted destination) into a task's
// whitelist map. The in-process per-tap registry is consulted first
// (tapName, zero-copy); a separate CLI process whose registry is empty
// falls back to the pinned map at WhitelistPinPath(taskID), which is how
// `agentpvm network whitelist add` reaches a running task's map. IPv4 only
// (the BPF map keys on __u32 daddr).
func AddWhitelistEntry(taskID, tapName, ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("network: invalid whitelist IP %q", ip)
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return fmt.Errorf("network: only IPv4 whitelist entries supported: %q", ip)
	}
	var key [4]byte
	copy(key[:], ip4)
	val := uint32(1)

	if tapName != "" {
		if m := WhitelistMapFor(tapName); m != nil {
			defer ReleaseWhitelistMap(tapName, m)
			return m.Update(&key, &val, ebpf.UpdateAny)
		}
	}
	pinPath, err := WhitelistPinPath(taskID)
	if err != nil {
		return err
	}
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return fmt.Errorf("network: failed to open pinned map %s: %w", pinPath, err)
	}
	defer m.Close()
	return m.Update(&key, &val, ebpf.UpdateAny)
}

// DeleteWhitelistEntry removes a previously whitelisted ip from a task's
// whitelist map (registry handle first, pinned-map fallback for separate
// CLI processes) — the map-side half of dnslearn's TTL expiry. A missing
// map (degraded task, no filter attached) surfaces as an error; callers
// that only maintain a table may ignore it. IPv4 only.
func DeleteWhitelistEntry(taskID, tapName, ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("network: invalid whitelist IP %q", ip)
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return fmt.Errorf("network: only IPv4 whitelist entries supported: %q", ip)
	}
	var key [4]byte
	copy(key[:], ip4)

	if tapName != "" {
		if m := WhitelistMapFor(tapName); m != nil {
			defer ReleaseWhitelistMap(tapName, m)
			return m.Delete(&key)
		}
	}
	pinPath, err := WhitelistPinPath(taskID)
	if err != nil {
		return err
	}
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return fmt.Errorf("network: failed to open pinned map %s: %w", pinPath, err)
	}
	defer m.Close()
	return m.Delete(&key)
}

// UnregisterWhitelistMap unregisters (and closes, once unreferenced) the
// whitelist map previously registered for tapName. Safe to call when
// nothing is attached. DetachTaskFilter calls this as part of the per-task
// teardown; it deliberately does NOT touch the clsact qdisc (see there).
func UnregisterWhitelistMap(tapName string) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	if e := whitelistTaps[tapName]; e != nil {
		retireLocked(tapName, e)
		delete(whitelistTaps, tapName)
	}
}
