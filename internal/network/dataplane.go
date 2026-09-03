package network

// dataplane.go — the bridgeless TC/eBPF data plane (opt-in via
// the TaskSpec's network.dataplane = "tc").
//
// Instead of a Linux bridge + iptables, every sandbox in tc mode gets the
// SAME fixed link-local addressing (guest TapDataplaneGuestIP, gateway/proxy
// TapDataplaneGatewayIP — identical inside every sandbox) and three TC
// programs (bpf/tap_dataplane.c) steer/NAT the traffic:
//
//	guest ──TAP ingress──► tap_ingress ──dst==169.254.68.5──► pvm-gw ingress ──► L7 proxy / DNS learner
//	                       │                                        (bound on 169.254.68.5:<port>)
//	                       └─whitelist+SSRF floor + SNAT──► bpf_redirect_neigh(host NIC) ──► world
//	world ──NIC ingress──► world_ingress ──session hit──► reverse DNAT ──► TAP TX ──► guest
//	proxy reply ──route 169.254.68.0/24 via pvm-gw──► gw_egress ──listener port──► TAP TX ──► guest
//
// The pvm-gw dummy device (169.254.68.5/32 + a link-scope route for
// 169.254.68.0/24) makes the fixed gateway address host-local so the L7
// egress proxy can bind 169.254.68.5:<port>; guest ARP for the gateway is
// answered by the host's weak-host model on the TAP.
//
// Failure contract mirrors AttachEgressFilter: every error is a typed
// *TapDataplaneError and StartTask degrades (audit security:
// degraded_warning) instead of failing the task — the L7 proxy remains the
// enforcement point.

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"uml-container/internal/metrics"
)

const (
	// TapDataplaneGuestIP is the fixed guest address in tc mode — the same
	// inside every sandbox (link-local; never routable off the host).
	TapDataplaneGuestIP = "169.254.68.6"
	// TapDataplaneGatewayIP is the fixed gateway/proxy address in tc mode.
	// It is assigned to the pvm-gw dummy device so host services (L7 egress
	// proxy, DNS-learn proxy) can bind it.
	TapDataplaneGatewayIP = "169.254.68.5"
	// gwDeviceName is the shared dummy device carrying TapDataplaneGatewayIP.
	gwDeviceName = "pvm-gw"
	// gwRouteCIDR routes the fixed link-local /24 via pvm-gw so proxy/DNS
	// replies to the guest traverse pvm-gw's egress (where gw_egress loops
	// them into the right TAP). More specific than the 169.254/16 link
	// routes some distros install on physical NICs; does not overlap the
	// cloud-metadata address 169.254.169.254.
	gwRouteCIDR = "169.254.68.0/24"

	// SNAT port window geometry (mirrored in bpf/tap_dataplane.c). Each
	// task owns 1024 consecutive source ports starting at a base derived
	// from the task id: 20000 + (fnv32(taskID) % 40000 rounded down to a
	// 1024-port block).
	snatPortBaseMin  = 20000
	snatPortBaseSpan = 40000
	snatPortWindow   = 1024

	// chainedHandleBase is the first TC filter handle tried on SHARED
	// devices (host NIC ingress, pvm-gw egress): several tc-mode tasks
	// chain their programs there, so handles are probed until free. The
	// task's own TAP uses fixed handle 1 (dedicated device).
	chainedHandleBase = 100
	chainedHandleMax  = chainedHandleBase + 64

	// Session idle timeouts are protocol-aware (the conntrack pattern):
	// TCP flows may legitimately sit silent for hours, while UDP "sessions"
	// (DNS, keepalives) that have not been replied to in minutes are dead.
	// Both dataplane programs refresh last_seen_ns on every packet they
	// forward, in either direction.
	tcpSessionIdleTimeout = 3 * time.Hour
	udpSessionIdleTimeout = 180 * time.Second
	// sessionSweepInterval is the sweeper's period; comfortably below the
	// UDP timeout so a dead UDP entry is gone within ~2 intervals.
	sessionSweepInterval = 30 * time.Second
	// sessionHighWater is the fill ratio of the LRU session map that trips
	// the high-water counter (scrappers page before the LRU starts
	// evicting live sessions silently).
	sessionHighWater = 0.8
)

// TapDataplaneError wraps every failure of the bridgeless dataplane
// attach/detach path. Op names the failing step (gw, link, route, addr,
// load, rewrite, qdisc, filter, pin, ...). StartTask treats ANY attach
// failure as degraded mode (audit security:degraded_warning, then bridge
// fallback when a bridge is configured); the typed error lets callers
// distinguish an environment gap (no root, no bpffs, kernel without
// clsact) from a programming bug.
type TapDataplaneError struct {
	Op  string
	Tap string
	Err error
}

func (e *TapDataplaneError) Error() string {
	return fmt.Sprintf("network: tc dataplane %s on %s: %v", e.Op, e.Tap, e.Err)
}
func (e *TapDataplaneError) Unwrap() error { return e.Err }

// PortBaseForTask derives the task's SNAT port window base:
// 20000 + (fnv32(taskID) % 40000 rounded down to 1024-port blocks), giving
// each task a mostly-disjoint 1024-port window in [20000, 60928). Different
// tasks CAN collide (the space is smaller than the task-id space); the BPF
// side retries colliding inserts within the window, and the reverse path
// demultiplexes per task, so a cross-task collision only wastes a port.
func PortBaseForTask(taskID string) uint32 {
	h := fnv.New32()
	_, _ = h.Write([]byte(taskID))
	return snatPortBaseMin + (h.Sum32()%snatPortBaseSpan)/snatPortWindow*snatPortWindow
}

// monotonicNanos returns CLOCK_MONOTONIC in nanoseconds — the same clock
// bpf_ktime_get_ns() writes into session_value.last_seen_ns.
func monotonicNanos() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// runIP shells out to iproute2 with a bounded timeout (consistent with
// tap.go's style). The combined output is included in errors: `ip` reports
// its reasons on stderr.
func runIP(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %v (%s)", args, err, out)
	}
	return nil
}

var gwDeviceMu sync.Mutex // serializes concurrent EnsureGwDevice calls

// EnsureGwDevice idempotently creates the shared pvm-gw dummy device with
// 169.254.68.5/32 and a link-scope route for 169.254.68.0/24 via it. It is
// never torn down: the device is shared by every tc-mode task and harmless
// when idle (a stray link-local /32 + route, like a leftover loopback
// alias). Returns the device ifindex. Requires root/CAP_NET_ADMIN; any
// failure is an environment gap the caller degrades on.
func EnsureGwDevice() (int, error) {
	gwDeviceMu.Lock()
	defer gwDeviceMu.Unlock()

	if _, err := netlink.LinkByName(gwDeviceName); err != nil {
		if err := runIP("link", "add", gwDeviceName, "type", "dummy"); err != nil {
			return 0, fmt.Errorf("create %s: %w", gwDeviceName, err)
		}
	}
	// Address/route are replace-semantics so a crashed earlier attempt or
	// an operator-managed device converges instead of erroring on EEXIST.
	if err := runIP("addr", "replace", TapDataplaneGatewayIP+"/32", "dev", gwDeviceName); err != nil {
		return 0, fmt.Errorf("assign %s/32 to %s: %w", TapDataplaneGatewayIP, gwDeviceName, err)
	}
	if err := runIP("link", "set", gwDeviceName, "up"); err != nil {
		return 0, fmt.Errorf("bring up %s: %w", gwDeviceName, err)
	}
	if err := runIP("route", "replace", gwRouteCIDR, "dev", gwDeviceName, "scope", "link"); err != nil {
		return 0, fmt.Errorf("route %s via %s: %w", gwRouteCIDR, gwDeviceName, err)
	}
	link, err := netlink.LinkByName(gwDeviceName)
	if err != nil {
		return 0, fmt.Errorf("resolve %s after setup: %w", gwDeviceName, err)
	}
	return link.Attrs().Index, nil
}

// defaultRouteNIC resolves the host NIC carrying the IPv4 default route
// (the SNAT egress device). The lowest-metric default wins; a gateway-less
// (point-to-point) default is accepted — bpf_redirect_neigh re-resolves
// the neighbor per packet. An empty default table is an error.
func defaultRouteNIC() (netlink.Link, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list IPv4 routes: %w", err)
	}
	var best *netlink.Route
	for i := range routes {
		r := &routes[i]
		if r.Dst != nil { // default routes have no Dst
			continue
		}
		if best == nil || r.Priority < best.Priority ||
			(r.Priority == best.Priority && best.Gw == nil && r.Gw != nil) {
			best = r
		}
	}
	if best == nil {
		return nil, errors.New("no IPv4 default route (tc dataplane needs one for SNAT egress)")
	}
	link, err := netlink.LinkByIndex(best.LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("default-route link %d: %w", best.LinkIndex, err)
	}
	return link, nil
}

// hostEgressIPv4 returns the NIC's first global-scope IPv4 address — the
// SNAT source guests get NATed to.
func hostEgressIPv4(link netlink.Link) (net.IP, error) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list addresses on %s: %w", link.Attrs().Name, err)
	}
	for _, a := range addrs {
		if ip4 := a.IP.To4(); ip4 != nil && a.Scope == unix.RT_SCOPE_UNIVERSE {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no global IPv4 address on %s", link.Attrs().Name)
}

// ensureClsact adds the clsact qdisc to link if missing (shared with the
// plain egress filter: EEXIST is success).
func ensureClsact(link netlink.Link) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("clsact on %s: %w", link.Attrs().Name, err)
	}
	return nil
}

// addBpfFilter attaches prog as a direct-action TC filter. On a DEDICATED
// device (the task TAP) the fixed handle 1 is used and a stale attachment
// from a crashed run is replaced. On SHARED devices (host NIC, pvm-gw) a
// free handle is probed starting at chainedHandleBase so multiple tasks
// chain. Returns the handle used (needed for symmetric detach).
func addBpfFilter(link netlink.Link, parent uint32, prog *ebpf.Program, name string, dedicated bool) (uint32, error) {
	mk := func(handle uint32) *netlink.BpfFilter {
		return &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    parent,
				Handle:    handle,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         name,
			DirectAction: true,
		}
	}
	if dedicated {
		if err := netlink.FilterAdd(mk(1)); err != nil {
			if errors.Is(err, unix.EEXIST) {
				if err := netlink.FilterReplace(mk(1)); err != nil {
					return 0, fmt.Errorf("replace %s on %s: %w", name, link.Attrs().Name, err)
				}
				return 1, nil
			}
			return 0, fmt.Errorf("attach %s on %s: %w", name, link.Attrs().Name, err)
		}
		return 1, nil
	}
	for h := uint32(chainedHandleBase); h < chainedHandleMax; h++ {
		err := netlink.FilterAdd(mk(h))
		switch {
		case err == nil:
			return h, nil
		case errors.Is(err, unix.EEXIST):
			continue // another task holds this handle
		default:
			return 0, fmt.Errorf("attach %s on %s (handle %d): %w", name, link.Attrs().Name, h, err)
		}
	}
	return 0, fmt.Errorf("no free tc filter handle on %s for %s", link.Attrs().Name, name)
}

// delBpfFilterAt removes a direct-action BPF filter by handle. Best-effort:
// a vanished device or replaced filter is not worth surfacing.
func delBpfFilterAt(linkName string, parent uint32, handle uint32) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return
	}
	_ = netlink.FilterDel(&netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    handle,
			Protocol:  unix.ETH_P_ALL,
		},
	})
}

// Pin file names under /sys/fs/bpf/pvm/<taskID>/ (the whitelist keeps the
// P1-A name/path so the CLI and dnslearn reach it unchanged).
const (
	pinEgressSessions = "egress_sessions"
	pinGwPortMap      = "gw_port_map"
	pinDpStats        = "dp_stats"
)

// TapDataplane is one task's attached bridgeless data plane. It owns the
// three TC filters, the per-task pinned maps and the session sweeper.
type TapDataplane struct {
	taskID  string
	tapName string
	hostNIC string
	hostIP  net.IP

	tapIfindex int
	nicIfindex int
	gwIfindex  int
	portBase   uint32

	tapHandle uint32 // TAP ingress handle (dedicated: always 1)
	nicHandle uint32 // host NIC ingress handle (chained)
	gwHandle  uint32 // pvm-gw egress handle (chained)

	sessions *ebpf.Map
	gwPorts  *ebpf.Map
	stats    *ebpf.Map
	progs    []*ebpf.Program

	// sessionMaxEntries caches the LRU map's capacity for the high-water
	// gauge (0 = unknown/unreadable).
	sessionMaxEntries uint32

	// whitelist is nil in the registry sense when shared: sharedHandle is
	// our extra fd onto the already-pinned/registered map (closed on
	// detach); an OWNED whitelist (no plain egress filter pinned one
	// first) is registered under the tap and closed by the registry.
	whitelistShared *ebpf.Map
	whitelistOwned  bool

	pinDir string

	cancel context.CancelFunc
	done   chan struct{}

	closed bool
}

// AttachTapDataplane loads bpf/tap_dataplane.c for ONE task, rewrites the
// per-task constants (host egress IP, ifindexes, port window base, fixed
// IPs), attaches the three programs (TAP ingress, host NIC ingress, pvm-gw
// egress), pins the session/gw-port/stats maps under
// /sys/fs/bpf/pvm/<taskID>/ and starts the idle-session sweeper.
//
// The whitelist_map is SHARED with the P1-A egress filter: when that filter
// pinned one first, it is swapped in via MapReplacements so both programs
// consult one policy map (whitelist CLI + dnslearn keep working). Otherwise
// the dataplane pins and registers its own under the same path/tap.
//
// hostNIC empty = resolve from the IPv4 default route. On error every
// loaded/attached/pinned resource is rolled back.
func AttachTapDataplane(taskID, tapName, hostNIC string) (*TapDataplane, error) {
	fail := func(op string, err error) (*TapDataplane, error) {
		return nil, &TapDataplaneError{Op: op, Tap: tapName, Err: err}
	}
	if !taskPinIDRe.MatchString(taskID) {
		return fail("validate", fmt.Errorf("invalid task id %q for bpf pin path", taskID))
	}
	if tapName == "" {
		return fail("validate", errors.New("empty tap name"))
	}
	pinDir, err := whitelistPinDir(taskID)
	if err != nil {
		return fail("validate", err)
	}
	whitelistPin, err := WhitelistPinPath(taskID)
	if err != nil {
		return fail("validate", err)
	}

	// Shared gateway device first: without it the proxy path cannot work,
	// so its setup failure fails the whole attach (typed, degraded by the
	// caller).
	gwIfindex, err := EnsureGwDevice()
	if err != nil {
		return fail("gw", err)
	}

	tapLink, err := netlink.LinkByName(tapName)
	if err != nil {
		return fail("link", fmt.Errorf("failed to get link %s: %w", tapName, err))
	}
	var nicLink netlink.Link
	if hostNIC != "" {
		nicLink, err = netlink.LinkByName(hostNIC)
		if err != nil {
			return fail("link", fmt.Errorf("failed to get link %s: %w", hostNIC, err))
		}
	} else {
		nicLink, err = defaultRouteNIC()
		if err != nil {
			return fail("route", err)
		}
	}
	hostIP, err := hostEgressIPv4(nicLink)
	if err != nil {
		return fail("addr", err)
	}

	spec, err := loadTapdp()
	if err != nil {
		return fail("load", err)
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"host_ip":          bpfIPv4(hostIP),
		"guest_ip":         bpfIPv4(net.ParseIP(TapDataplaneGuestIP)),
		"proxy_ip":         bpfIPv4(net.ParseIP(TapDataplaneGatewayIP)),
		"host_nic_ifindex": uint32(nicLink.Attrs().Index),
		"gw_dev_ifindex":   uint32(gwIfindex),
		"tap_dev_ifindex":  uint32(tapLink.Attrs().Index),
		"port_base":        PortBaseForTask(taskID),
	}); err != nil {
		return fail("rewrite", err)
	}

	// Share the already-pinned whitelist map when present (the P1-A egress
	// filter owns it then); otherwise the dataplane pins its own below.
	var sharedWl *ebpf.Map
	opts := &ebpf.CollectionOptions{}
	if m, lerr := ebpf.LoadPinnedMap(whitelistPin, nil); lerr == nil {
		sharedWl = m
		opts.MapReplacements = map[string]*ebpf.Map{"whitelist_map": m}
	}
	var objs tapdpObjects
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
		if sharedWl != nil {
			_ = sharedWl.Close()
		}
		return fail("load", err)
	}

	d := &TapDataplane{
		taskID:     taskID,
		tapName:    tapName,
		hostNIC:    nicLink.Attrs().Name,
		hostIP:     hostIP,
		tapIfindex: tapLink.Attrs().Index,
		nicIfindex: nicLink.Attrs().Index,
		gwIfindex:  gwIfindex,
		portBase:   PortBaseForTask(taskID),
		sessions:   objs.EgressSessions,
		gwPorts:    objs.GwPortMap,
		stats:      objs.DpStats,
		progs:      []*ebpf.Program{objs.TapIngress, objs.WorldIngress, objs.GwEgress},
		pinDir:     pinDir,
	}
	if info, ierr := objs.EgressSessions.Info(); ierr == nil {
		d.sessionMaxEntries = info.MaxEntries
	}
	if sharedWl != nil {
		d.whitelistShared = sharedWl // objs.WhitelistMap aliases it
	} else {
		d.whitelistOwned = true
	}
	// From here on, rollback releases whatever this attach acquired.
	success := false
	pinned := false
	defer func() {
		if success {
			return
		}
		d.removeFilters()
		if pinned {
			d.removePins()
		}
		_ = objs.TapIngress.Close()
		_ = objs.WorldIngress.Close()
		_ = objs.GwEgress.Close()
		_ = objs.EgressSessions.Close()
		_ = objs.GwPortMap.Close()
		_ = objs.DpStats.Close()
		// The whitelist is either our handle onto the pinned shared map
		// (aliases objs.WhitelistMap) or a freshly created map we own.
		if sharedWl != nil {
			_ = sharedWl.Close()
		} else {
			_ = objs.WhitelistMap.Close()
		}
	}()

	// 1. TAP ingress: policy + SNAT + session create + redirect.
	if err := ensureClsact(tapLink); err != nil {
		return fail("qdisc", err)
	}
	if _, err := addBpfFilter(tapLink, netlink.HANDLE_MIN_INGRESS, objs.TapIngress, "tap_ingress", true); err != nil {
		return fail("filter", err)
	}
	d.tapHandle = 1

	// 2. Host NIC ingress: reverse DNAT via the session table.
	nicGwLink, err := netlink.LinkByIndex(gwIfindex)
	if err != nil {
		return fail("link", fmt.Errorf("resolve %s: %w", gwDeviceName, err))
	}
	if err := ensureClsact(nicLink); err != nil {
		return fail("qdisc", err)
	}
	nicHandle, err := addBpfFilter(nicLink, netlink.HANDLE_MIN_INGRESS, objs.WorldIngress, "world_ingress", false)
	if err != nil {
		return fail("filter", err)
	}
	d.nicHandle = nicHandle

	// 3. pvm-gw egress: proxy/DNS reply loop into the owning TAP.
	if err := ensureClsact(nicGwLink); err != nil {
		return fail("qdisc", err)
	}
	gwHandle, err := addBpfFilter(nicGwLink, netlink.HANDLE_MIN_EGRESS, objs.GwEgress, "gw_egress", false)
	if err != nil {
		return fail("filter", err)
	}
	d.gwHandle = gwHandle

	// 4. Pins. A missing/read-only bpffs fails here AFTER the filters are
	// attached — roll them back (degraded tasks never run with programs
	// nobody can inspect), same contract as AttachEgressFilter.
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return fail("pin", fmt.Errorf("create pin dir %s: %w", pinDir, err))
	}
	pinned = true // from here on, roll back whatever pins already happened
	for _, p := range []struct {
		name string
		m    *ebpf.Map
	}{
		{pinEgressSessions, objs.EgressSessions},
		{pinGwPortMap, objs.GwPortMap},
		{pinDpStats, objs.DpStats},
	} {
		if err := p.m.Pin(filepath.Join(pinDir, p.name)); err != nil {
			return fail("pin", fmt.Errorf("pin %s: %w", p.name, err))
		}
	}
	if d.whitelistOwned {
		if err := objs.WhitelistMap.Pin(whitelistPin); err != nil {
			return fail("pin", fmt.Errorf("pin whitelist_map: %w", err))
		}
	}

	// 5. Registry + sweeper. An owned whitelist is registered under the
	// tap (registry owns/ closes it, exactly like AttachEgressFilter).
	if d.whitelistOwned {
		registerWhitelistMap(tapName, objs.WhitelistMap)
	}

	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	d.done = make(chan struct{})
	go d.sweeper(ctx)

	dataplaneMu.Lock()
	if old := dataplanes[taskID]; old != nil {
		// Re-attach of a live task: retire the old attachment first so two
		// filter sets never coexist for one task id.
		dataplaneMu.Unlock()
		_ = old.Close()
		dataplaneMu.Lock()
	}
	dataplanes[taskID] = d
	dataplaneMu.Unlock()

	success = true
	return d, nil
}

// removeFilters deletes the three TC filters this attach installed.
// Best-effort: each deletion tolerates a vanished device.
func (d *TapDataplane) removeFilters() {
	if d.tapHandle != 0 {
		delBpfFilterAt(d.tapName, netlink.HANDLE_MIN_INGRESS, d.tapHandle)
	}
	if d.nicHandle != 0 {
		delBpfFilterAt(d.hostNIC, netlink.HANDLE_MIN_INGRESS, d.nicHandle)
	}
	if d.gwHandle != 0 {
		delBpfFilterAt(gwDeviceName, netlink.HANDLE_MIN_EGRESS, d.gwHandle)
	}
}

// removePins deletes this task's pinned maps and pin dir. The dir removal
// only succeeds when empty, so a dir shared with the P1-A filter (whitelist
// pin) is never pulled from under it — unless we own the last pin.
func (d *TapDataplane) removePins() {
	for _, name := range []string{pinEgressSessions, pinGwPortMap, pinDpStats} {
		_ = os.Remove(filepath.Join(d.pinDir, name))
	}
	if d.whitelistOwned {
		if p, err := WhitelistPinPath(d.taskID); err == nil {
			_ = os.Remove(p)
		}
	}
	_ = os.Remove(d.pinDir) // fails harmlessly when non-empty
}

// sweeper deletes NAT sessions idle beyond their protocol's timeout
// (the conntrack-reaper pattern) and publishes capacity gauges. Both
// dataplane programs refresh last_seen_ns on every packet they forward,
// so only genuinely idle entries expire. The LRU map itself bounds total
// memory; the high-water counter fires before silent LRU eviction starts.
func (d *TapDataplane) sweeper(ctx context.Context) {
	defer close(d.done)
	t := time.NewTicker(sessionSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.sweepOnce(0)
			d.publishCapacity()
		}
	}
}

// sessionIdleFor returns the idle cutoff multiplier per protocol: TCP
// sessions survive long silent stretches, UDP ones do not.
func sessionIdleFor(proto uint8) time.Duration {
	if proto == 6 { // IPPROTO_TCP
		return tcpSessionIdleTimeout
	}
	return udpSessionIdleTimeout
}

// sweepOnce removes stale session entries; returns how many were deleted.
// The legacy single-timeout form is kept for callers/tests that want a
// uniform cutoff; the sweeper passes 0 to select the per-protocol timeout.
// Iteration of an LRU hash under concurrent dataplane updates is inherently
// approximate — keys are collected first, deletes happen after, and a
// vanished-already entry is not an error.
func (d *TapDataplane) sweepOnce(uniform time.Duration) int {
	if d.sessions == nil {
		return 0
	}
	now := monotonicNanos()
	cutoffFor := func(k tapdpSessionKey) uint64 {
		idle := sessionIdleFor(k.Proto)
		if uniform > 0 {
			idle = uniform
		}
		if now < uint64(idle) {
			return 0 // host younger than the timeout: nothing can be stale
		}
		return now - uint64(idle)
	}
	var stale []tapdpSessionKey
	var (
		k tapdpSessionKey
		v tapdpSessionValue
	)
	iter := d.sessions.Iterate()
	for iter.Next(&k, &v) {
		if v.LastSeenNs < cutoffFor(k) {
			stale = append(stale, k)
		}
	}
	deleted := 0
	for i := range stale {
		if err := d.sessions.Delete(&stale[i]); err == nil {
			deleted++
		}
	}
	return deleted
}

// dpSessionsGauge / dpSessionHighWater are the capacity observability
// handles for the per-task NAT session table.
var (
	dpSessionsGauge    = metrics.Gauge("pvm_dp_sessions", "NAT sessions currently tracked by the tc dataplane", "task")
	dpSessionHighWater = metrics.Counter("pvm_dp_session_high_water_total", "tc dataplane session table crossed the high-water mark", "task")
)

// highWaterTripped reports whether the fill ratio crosses the high-water
// mark (pure — the sweeper path and tests share it).
func highWaterTripped(n int, maxEntries uint32) bool {
	if maxEntries == 0 || n < 0 {
		return false
	}
	return float64(n)/float64(maxEntries) > sessionHighWater
}

// publishCapacity records the session-table fill level. MaxEntries comes
// from the map definition (LRU-bounded); an unreadable map is reported as
// gauge only.
func (d *TapDataplane) publishCapacity() {
	if d.sessions == nil {
		return
	}
	n := d.sessionCount()
	if n < 0 {
		return
	}
	dpSessionsGauge.Set(float64(n), d.taskID)
	if highWaterTripped(n, d.sessionMaxEntries) {
		dpSessionHighWater.Inc(d.taskID)
	}
}

// Close is the symmetric teardown of AttachTapDataplane: stop the sweeper,
// remove the three TC filters, unpin the maps, unregister the whitelist
// (when owned) and release every kernel fd. Idempotent.
func (d *TapDataplane) Close() error {
	dataplaneMu.Lock()
	if d.closed {
		dataplaneMu.Unlock()
		return nil
	}
	d.closed = true
	if dataplanes[d.taskID] == d {
		delete(dataplanes, d.taskID)
	}
	dataplaneMu.Unlock()

	if d.cancel != nil {
		d.cancel()
		<-d.done
	}
	d.removeFilters()
	d.removePins()
	dpSessionsGauge.Delete(d.taskID)
	if d.whitelistOwned {
		UnregisterWhitelistMap(d.tapName) // registry closes the map
	}
	if d.whitelistShared != nil {
		_ = d.whitelistShared.Close()
	}
	for _, p := range d.progs {
		if p != nil {
			_ = p.Close()
		}
	}
	for _, m := range []*ebpf.Map{d.sessions, d.gwPorts, d.stats} {
		if m != nil {
			_ = m.Close()
		}
	}
	return nil
}

// DetachTapDataplane tears down taskID's dataplane. When the attachment is
// registered in-process it is fully closed; otherwise (e.g. cleanup after a
// crash) the pinned maps are removed best-effort — stale NIC/pvm-gw filters
// from a dead process are inert (their maps are gone, every lookup misses,
// packets pass) and can be cleared manually with `tc filter del`.
// Permission errors on the best-effort leg are treated like "not there":
// StartTask defers this unconditionally (even when nothing was attached,
// e.g. attach degraded without root), so an unprivileged process probing
// /sys/fs/bpf must not turn a no-op detach into an error (CI runs the unit
// tests as non-root where every bpffs path is EACCES).
func DetachTapDataplane(taskID string) error {
	dataplaneMu.Lock()
	d := dataplanes[taskID]
	dataplaneMu.Unlock()
	if d != nil {
		return d.Close()
	}
	var errs []error
	if pinDir, err := whitelistPinDir(taskID); err == nil {
		for _, name := range []string{pinEgressSessions, pinGwPortMap, pinDpStats} {
			if err := os.Remove(filepath.Join(pinDir, name)); err != nil && !benignDetachErr(err) {
				errs = append(errs, fmt.Errorf("unpin %s: %w", name, err))
			}
		}
		if err := os.Remove(pinDir); err != nil && !benignDetachErr(err) && !errors.Is(err, unix.ENOTEMPTY) {
			errs = append(errs, fmt.Errorf("remove pin dir %s: %w", pinDir, err))
		}
	}
	return errors.Join(errs...)
}

// ---------------------------------------------------------------------------
// Registry + status views (consumed by internal/api's /network/dataplane).

var (
	dataplaneMu sync.Mutex
	dataplanes  = map[string]*TapDataplane{}
)

// dpStatNames maps the dp_stats array indexes to stable API names; keep in
// sync with the ST_* constants in bpf/tap_dataplane.c.
var dpStatNames = []string{
	"drop_policy",  // SSRF floor or whitelist denied
	"drop_proto",   // ICMP / non-TCP-UDP / IPv6 / IP options
	"drop_nat",     // no free SNAT port in the task window
	"sessions_new", // NAT sessions created
	"nat_fwd",      // SNATed packets redirected to the world
	"gw_fwd",       // packets redirected to the host stack via pvm-gw
	"rev_fwd",      // reverse-DNATed packets redirected to the TAP
	"gw_loop",      // proxy/DNS replies looped back into the TAP
}

// DataplaneTaskStatus is the REST-facing per-task view of an attached tc
// data plane.
type DataplaneTaskStatus struct {
	TaskID     string            `json:"task"`
	Mode       string            `json:"mode"` // always "tc" for attached tasks
	TAP        string            `json:"tap"`
	HostNIC    string            `json:"host_nic"`
	HostIP     string            `json:"host_ip"`
	GuestIP    string            `json:"guest_ip"`
	GatewayIP  string            `json:"gateway_ip"`
	PortBase   uint32            `json:"port_base"`
	PortWindow uint32            `json:"port_window"`
	PinDir     string            `json:"pin_dir"`
	Programs   []string          `json:"programs"`
	Sessions   int               `json:"sessions"` // -1 = unreadable
	Stats      map[string]uint64 `json:"stats"`
}

// sessionCount counts entries in the (LRU) session map. Bounded iteration:
// the map caps at 4096 entries. An unreadable map reports -1.
func (d *TapDataplane) sessionCount() int {
	if d.sessions == nil {
		return -1
	}
	var (
		k tapdpSessionKey
		v tapdpSessionValue
	)
	n := 0
	iter := d.sessions.Iterate()
	for iter.Next(&k, &v) {
		n++
	}
	return n
}

// readStats snapshots the dp_stats counters; nil map → empty map.
func (d *TapDataplane) readStats() map[string]uint64 {
	out := make(map[string]uint64, len(dpStatNames))
	if d.stats == nil {
		return out
	}
	for i, name := range dpStatNames {
		key := uint32(i)
		var val uint64
		if err := d.stats.Lookup(&key, &val); err == nil {
			out[name] = val
		}
	}
	return out
}

// status renders the live view of this dataplane.
func (d *TapDataplane) status() DataplaneTaskStatus {
	return DataplaneTaskStatus{
		TaskID:     d.taskID,
		Mode:       "tc",
		TAP:        d.tapName,
		HostNIC:    d.hostNIC,
		HostIP:     d.hostIP.String(),
		GuestIP:    TapDataplaneGuestIP,
		GatewayIP:  TapDataplaneGatewayIP,
		PortBase:   d.portBase,
		PortWindow: snatPortWindow,
		PinDir:     d.pinDir,
		Programs: []string{
			fmt.Sprintf("tap_ingress@%s:ingress(h=%d)", d.tapName, d.tapHandle),
			fmt.Sprintf("world_ingress@%s:ingress(h=%d)", d.hostNIC, d.nicHandle),
			fmt.Sprintf("gw_egress@%s:egress(h=%d)", gwDeviceName, d.gwHandle),
		},
		Sessions: d.sessionCount(),
		Stats:    d.readStats(),
	}
}

// DataplaneStatus returns the per-task status of every currently attached
// tc dataplane (empty when none). Bridge-mode tasks never appear here.
func DataplaneStatus() []DataplaneTaskStatus {
	dataplaneMu.Lock()
	ds := make([]*TapDataplane, 0, len(dataplanes))
	for _, d := range dataplanes {
		ds = append(ds, d)
	}
	dataplaneMu.Unlock()
	out := make([]DataplaneTaskStatus, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.status())
	}
	return out
}

// DataplaneStatusFor returns one task's tc dataplane status; ok=false when
// the task has no attached tc dataplane (bridge mode, degraded, or gone).
func DataplaneStatusFor(taskID string) (DataplaneTaskStatus, bool) {
	dataplaneMu.Lock()
	d, ok := dataplanes[taskID]
	dataplaneMu.Unlock()
	if !ok {
		return DataplaneTaskStatus{}, false
	}
	return d.status(), true
}

// GwDeviceStatus reports the shared pvm-gw device posture for the API:
// whether it exists, its ifindex and addresses. Read-only and
// privilege-free (netlink reads need no root).
func GwDeviceStatus() map[string]interface{} {
	out := map[string]interface{}{
		"name":       gwDeviceName,
		"exists":     false,
		"gateway_ip": TapDataplaneGatewayIP,
		"route":      gwRouteCIDR,
	}
	link, err := netlink.LinkByName(gwDeviceName)
	if err != nil {
		return out
	}
	out["exists"] = true
	out["ifindex"] = link.Attrs().Index
	if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err == nil {
		list := make([]string, 0, len(addrs))
		for _, a := range addrs {
			list = append(list, a.IPNet.String())
		}
		out["addrs"] = list
	}
	return out
}
