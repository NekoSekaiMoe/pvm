// Package dnslearn implements DNS-learned domain egress policy (todo.md
// P1-B, modelled on CubeSandbox CubeVS's dns_allow/dns_query_track): a
// per-task UDP DNS proxy snoops resolver responses, and the resolved PUBLIC
// IPs of allowlisted domains are inserted into the task's eBPF whitelist
// map (internal/network filter registry) with TTL-bounded expiry. The IP
// floor then admits exactly the addresses the guest itself resolved, instead
// of a static operator-maintained IP list.
//
// Safety invariants:
//   - ONLY domains matching the task's L7 allowlist are ever learned, and
//     the matching semantics are REUSED from the egress gateway
//     (egress.DomainMatches) so both enforcement layers agree.
//   - Only public IPv4 addresses are inserted; private/loopback/link-local/
//     CGNAT/multicast answers are ignored (the BPF whitelist_map is keyed on
//     a __u32 IPv4 daddr — AAAA/IPv6 learning is future work and requires a
//     second map + BPF program changes).
//   - Map writes are best-effort: when the per-task TC filter is degraded
//     (no root/bpffs), the learner still tracks the table (feeding the
//     gateway's rebinding guard) but skips the map. Failures are tolerated
//     and logged, never fatal — DNS learning is advisory on top of the L7
//     proxy, which remains the enforcement point.
package dnslearn

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"uml-container/internal/audit"
	"uml-container/internal/network"
	"uml-container/internal/network/egress"
)

// Defaults mirror spec.DefaultLearnTTL / spec.DefaultMaxLearnedEntries; they
// are restated here (as durations/ints, not TOML strings) so a Learner built
// without going through the spec loader is still bounded.
const (
	DefaultLearnTTL    = 5 * time.Minute
	DefaultMaxEntries  = 256
	defaultSweepEvery  = time.Second
	dnsProxyBufferSize = 4096 // comfortably covers EDNS0 UDP payloads
)

// MapWriter is the per-task eBPF whitelist-map sink. Implementations must be
// safe for concurrent use; errors are tolerated by the Learner (degraded
// mode) so implementations should return them, not panic.
type MapWriter interface {
	AddWhitelist(ip string) error
	DeleteWhitelist(ip string) error
}

// FilterMapWriter writes through the network package's per-task filter
// registry (in-process map handle, falling back to the bpffs pinned map at
// /sys/fs/bpf/pvm/<taskID>/whitelist_map — the same path the whitelist CLI
// uses). When the task's TC filter was never attached both paths fail; the
// Learner tolerates that as table-only degraded mode.
type FilterMapWriter struct {
	TaskID  string
	TapName string
}

// AddWhitelist inserts ip into the task's whitelist map.
func (w FilterMapWriter) AddWhitelist(ip string) error {
	return network.AddWhitelistEntry(w.TaskID, w.TapName, ip)
}

// DeleteWhitelist removes ip from the task's whitelist map.
func (w FilterMapWriter) DeleteWhitelist(ip string) error {
	return network.DeleteWhitelistEntry(w.TaskID, w.TapName, ip)
}

// Config builds a Learner for one task.
type Config struct {
	// TaskID scopes the table, the audit ledger and (for FilterMapWriter)
	// the pinned-map path. Required.
	TaskID string
	// AllowDomains is the L7 allowlist (exact or "*.suffix"), typically
	// spec.Network.EgressAllowDomains plus the hosts of allow EgressRules.
	AllowDomains []string
	// LearnTTL caps a learned entry's lifetime; the effective TTL of every
	// insert is min(DNS answer TTL, LearnTTL). <= 0 selects DefaultLearnTTL.
	LearnTTL time.Duration
	// Upstream is the resolver the DNS proxy forwards to: "IP" or "IP:port".
	// Empty selects the first /etc/resolv.conf nameserver (1.1.1.1:53 last).
	Upstream string
	// MaxEntries bounds the total learned (domain, ip) pairs per task so a
	// guest flooding distinct allowlisted lookups cannot exhaust map
	// capacity or host memory. <= 0 selects DefaultMaxEntries.
	MaxEntries int
	// Ledger receives dns:learn / dns:expire / security:degraded_warning
	// records. Nil disables auditing (tests).
	Ledger *audit.Ledger
	// Writer receives map inserts/deletes. Nil selects a FilterMapWriter
	// keyed on TaskID (+TapName); pass an explicit nil-writer surrogate in
	// tests via NopWriter.
	Writer MapWriter
	// TapName names the tap whose registry whitelist map receives writes.
	TapName string
}

// LearnedEntry is one live (domain, ip) pair with its expiry.
type LearnedEntry struct {
	Domain string    `json:"domain"`
	IP     string    `json:"ip"`
	Expiry time.Time `json:"expiry"`
	// RemainingSec is the whole seconds until expiry at List() time.
	RemainingSec int `json:"remaining_sec"`
}

type entry struct {
	ip     string
	expiry time.Time
}

// Learner is the per-task DNS-learn engine: an allowlist-guarded table of
// domain -> [{ip, expiry}] mirrored into the task's whitelist map, swept for
// TTL expiry, and (optionally) fronted by a snooping UDP DNS proxy.
type Learner struct {
	taskID string
	writer MapWriter
	ledger *audit.Ledger

	mu         sync.Mutex
	enabled    bool
	allow      []string // normalized rules (lower, trailing dot stripped)
	maxTTL     time.Duration
	maxEntries int
	upstream   string // host:port, resolved at construction
	learned    map[string][]entry
	total      int // live entries across all domains
	dropped    int // inserts refused by the max-entries cap

	sweepEvery time.Duration
	now        func() time.Time // test hook; defaults to time.Now

	proxy  *Proxy
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed bool
}

// New constructs a Learner from cfg, resolving defaults.
func New(cfg Config) (*Learner, error) {
	if cfg.TaskID == "" {
		return nil, fmt.Errorf("dnslearn: task id required")
	}
	l := &Learner{
		taskID:     cfg.TaskID,
		ledger:     cfg.Ledger,
		enabled:    true,
		maxTTL:     cfg.LearnTTL,
		maxEntries: cfg.MaxEntries,
		learned:    map[string][]entry{},
		sweepEvery: defaultSweepEvery,
		now:        time.Now,
	}
	if l.maxTTL <= 0 {
		l.maxTTL = DefaultLearnTTL
	}
	if l.maxEntries <= 0 {
		l.maxEntries = DefaultMaxEntries
	}
	up, err := normalizeUpstream(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	l.upstream = up
	for _, d := range cfg.AllowDomains {
		l.allow = append(l.allow, normalizeName(d))
	}
	if cfg.Writer != nil {
		l.writer = cfg.Writer
	} else {
		l.writer = FilterMapWriter{TaskID: cfg.TaskID, TapName: cfg.TapName}
	}
	return l, nil
}

// NopWriter is an explicit table-only MapWriter for tests and for tasks
// whose eBPF filter is known-degraded: every write succeeds as a no-op.
type NopWriter struct{}

// AddWhitelist is a no-op.
func (NopWriter) AddWhitelist(ip string) error { return nil }

// DeleteWhitelist is a no-op.
func (NopWriter) DeleteWhitelist(ip string) error { return nil }

// normalizeName lowercases and strips the DNS trailing dot so wire-format
// qnames ("example.com.") and policy rules ("example.com") compare equal.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// cgnatNet is 100.64.0.0/10 (RFC 6598 shared address space): not routable on
// the public internet, and net.IP.IsPrivate does not cover it.
var cgnatNet = &net.IPNet{
	IP:   net.ParseIP("100.64.0.0"),
	Mask: net.CIDRMask(10, 32),
}

// isPublicIPv4 reports whether ip is a globally routable IPv4 address worth
// whitelisting. Private, loopback, link-local, multicast, unspecified and
// CGNAT answers are refused: a malicious (or compromised) upstream answering
// an allowlisted name with an internal address must not open the eBPF floor
// to that address.
func isPublicIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return !(ip4.IsPrivate() || ip4.IsLoopback() ||
		ip4.IsLinkLocalUnicast() || ip4.IsLinkLocalMulticast() ||
		ip4.IsMulticast() || ip4.IsUnspecified() || cgnatNet.Contains(ip4))
}

// IsAllowlisted reports whether domain matches the task's allowlist using
// the SAME semantics as the L7 egress proxy (exact or "*.suffix" wildcard).
func (l *Learner) IsAllowlisted(domain string) bool {
	d := normalizeName(domain)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, rule := range l.allow {
		if egress.DomainMatches(d, rule) {
			return true
		}
	}
	return false
}

// ProcessResponse consumes one snooped DNS answer: qname is the question
// name, ips the A-record answers, ttl their (minimum) TTL in seconds. Each
// public IPv4 of an ALLOWLISTED qname is inserted with expiry =
// now + min(ttl, learn_ttl); anything else (non-allowlisted name, private
// IP, IPv6 answer) is ignored. Returns the number of entries inserted or
// refreshed. A zero TTL means "do not cache" per RFC 1035 and is skipped.
func (l *Learner) ProcessResponse(qname string, ips []net.IP, ttl uint32) int {
	domain := normalizeName(qname)
	if ttl == 0 || len(ips) == 0 {
		return 0
	}
	lifetime := time.Duration(ttl) * time.Second

	l.mu.Lock()
	if !l.enabled {
		l.mu.Unlock()
		return 0
	}
	allowed := false
	for _, rule := range l.allow {
		if egress.DomainMatches(domain, rule) {
			allowed = true
			break
		}
	}
	if !allowed {
		l.mu.Unlock()
		return 0
	}
	if lifetime > l.maxTTL {
		lifetime = l.maxTTL
	}
	expiry := l.now().Add(lifetime)

	type insert struct {
		ip        string
		refreshed bool
	}
	var inserts []insert
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil || !isPublicIPv4(ip4) {
			continue
		}
		s := ip4.String()
		found := false
		for i, e := range l.learned[domain] {
			if e.ip == s {
				// Refresh in place: the guest re-resolved the name, so the
				// address is still what the guest sees.
				l.learned[domain][i].expiry = expiry
				found = true
				inserts = append(inserts, insert{ip: s, refreshed: true})
				break
			}
		}
		if found {
			continue
		}
		if l.total >= l.maxEntries {
			l.dropped++
			continue
		}
		l.learned[domain] = append(l.learned[domain], entry{ip: s, expiry: expiry})
		l.total++
		inserts = append(inserts, insert{ip: s})
	}
	writer := l.writer
	l.mu.Unlock()

	learned := 0
	for _, in := range inserts {
		if writer != nil {
			// Best-effort: a degraded task has no reachable map. The table
			// entry (and audit row) still stand — the gateway's rebinding
			// guard consumes the table even without the BPF floor.
			if err := writer.AddWhitelist(in.ip); err != nil {
				log.Printf("dnslearn: whitelist map add %s for task %s failed (degraded): %v",
					in.ip, l.taskID, err)
			}
		}
		learned++
		l.audit("dns:learn", map[string]interface{}{
			"domain": domain, "ip": in.ip,
			"ttl": int(lifetime / time.Second), "expiry": expiry.UTC().Format(time.RFC3339),
			"refresh": in.refreshed,
		}, fmt.Sprintf("learned %s -> %s (ttl %ds, cap %ds)", domain, in.ip,
			int(lifetime/time.Second), int(l.maxTTL/time.Second)))
	}
	return learned
}

// List returns the live learned entries, sorted for a stable API response.
func (l *Learner) List() []LearnedEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	out := make([]LearnedEntry, 0, l.total)
	for domain, es := range l.learned {
		for _, e := range es {
			if !e.expiry.After(now) {
				continue // pending sweep; hide rather than leak a stale row
			}
			out = append(out, LearnedEntry{
				Domain:       domain,
				IP:           e.ip,
				Expiry:       e.expiry,
				RemainingSec: int(e.expiry.Sub(now).Seconds()),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// LearnedIPs returns the live learned IPs for host (registry-checker
// semantics for the egress rebinding guard): nil when nothing was learned.
func (l *Learner) LearnedIPs(host string) []net.IP {
	domain := normalizeName(host)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var out []net.IP
	for _, e := range l.learned[domain] {
		if e.expiry.After(now) {
			out = append(out, net.ParseIP(e.ip))
		}
	}
	return out
}

// Drop removes every learned entry for host, deleting each from the map.
// Returns the number dropped.
// ipStillReferenced reports whether ip remains live under any domain other
// than skipDomain. Callers must hold l.mu. Two allowlisted domains commonly
// share a CDN IP; deleting the whitelist entry while the other domain still
// holds it would drop that traffic at the data plane until the next learn.
// Callers must hold l.mu. An entry whose TTL already elapsed but which
// sweep has not collected yet is NOT a live reference: counting it would
// keep the shared whitelist entry past the other domain's expiry.
func (l *Learner) ipStillReferenced(skipDomain, ip string, now time.Time) bool {
	for domain, es := range l.learned {
		if domain == skipDomain {
			continue
		}
		for _, e := range es {
			if e.ip == ip && e.expiry.After(now) {
				return true
			}
		}
	}
	return false
}

func (l *Learner) Drop(host string) int {
	domain := normalizeName(host)
	l.mu.Lock()
	now := l.now()
	es := l.learned[domain]
	delete(l.learned, domain)
	l.total -= len(es)
	// Collect the deletions that are safe: an IP shared with a still-live
	// domain entry must stay in the whitelist map.
	var doomed []entry
	for _, e := range es {
		if !l.ipStillReferenced(domain, e.ip, now) {
			doomed = append(doomed, e)
		}
	}
	writer := l.writer
	l.mu.Unlock()

	for _, e := range doomed {
		if writer != nil {
			if err := writer.DeleteWhitelist(e.ip); err != nil {
				log.Printf("dnslearn: whitelist map delete %s for task %s failed: %v",
					e.ip, l.taskID, err)
			}
		}
	}
	for _, e := range es { // every dropped entry is audited, shared or not
		l.audit("dns:expire", map[string]interface{}{
			"domain": domain, "ip": e.ip, "expiry": e.expiry.UTC().Format(time.RFC3339),
		}, fmt.Sprintf("dropped %s -> %s via API", domain, e.ip))
	}
	return len(es)
}

// AddAllow promotes domain into the task's runtime allowlist (the
// POST /api/egress/:task/allow contract). Returns false when already present.
func (l *Learner) AddAllow(domain string) bool {
	d := normalizeName(domain)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, rule := range l.allow {
		if rule == d {
			return false
		}
	}
	l.allow = append(l.allow, d)
	return true
}

// AllowList returns a copy of the current allowlist rules.
func (l *Learner) AllowList() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.allow...)
}

// SetEnabled toggles learning (the PUT policy contract). Disabling never
// stops DNS forwarding — the proxy stays transparent — and does not flush
// already-learned entries (they expire naturally).
func (l *Learner) SetEnabled(on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = on
}

// Enabled reports the current learn-mode toggle.
func (l *Learner) Enabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enabled
}

// SetLearnTTL changes the TTL cap for FUTURE inserts (existing entries keep
// their expiry).
func (l *Learner) SetLearnTTL(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxTTL = d
}

// LearnTTL returns the current TTL cap.
func (l *Learner) LearnTTL() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxTTL
}

// MaxEntries returns the learned-entry cap.
func (l *Learner) MaxEntries() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxEntries
}

// Upstream returns the resolver address (host:port) the proxy forwards to.
func (l *Learner) Upstream() string { return l.upstream }

// TaskID returns the owning task id.
func (l *Learner) TaskID() string { return l.taskID }

// Dropped returns how many inserts the max-entries cap has refused.
func (l *Learner) Dropped() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

// Count returns the number of live table entries.
func (l *Learner) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// Run starts the background sweeper: expired entries are deleted from BOTH
// the table and the whitelist map, each with a dns:expire audit row. It
// returns immediately; the sweeper stops on ctx cancel or Close.
func (l *Learner) Run(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithCancel(ctx)
	l.mu.Lock()
	if l.cancel != nil { // already running
		l.mu.Unlock()
		cancel()
		return
	}
	l.cancel = cancel
	interval := l.sweepEvery
	l.mu.Unlock()

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case <-t.C:
				l.sweep()
			}
		}
	}()
}

// sweep deletes expired entries from table and map. Extracted from the
// ticker loop so tests can drive it deterministically.
func (l *Learner) sweep() {
	type expired struct {
		domain string
		e      entry
	}
	var dead []expired
	l.mu.Lock()
	now := l.now()
	for domain, es := range l.learned {
		keep := es[:0]
		for _, e := range es {
			if e.expiry.After(now) {
				keep = append(keep, e)
			} else {
				dead = append(dead, expired{domain, e})
				l.total--
			}
		}
		if len(keep) == 0 {
			delete(l.learned, domain)
		} else {
			l.learned[domain] = keep
		}
	}
	// Prune the deletions: every entry in `dead` is already gone from the
	// table, so ipStillReferenced reflects the post-expiry state — an IP
	// still held by a live (non-expired) domain entry stays in the
	// whitelist map (shared-CDN case).
	var doomed []expired
	for _, d := range dead {
		if !l.ipStillReferenced(d.domain, d.e.ip, now) {
			doomed = append(doomed, d)
		}
	}
	writer := l.writer
	l.mu.Unlock()

	for _, d := range doomed {
		if writer != nil {
			if err := writer.DeleteWhitelist(d.e.ip); err != nil {
				log.Printf("dnslearn: whitelist map expire-delete %s for task %s failed: %v",
					d.e.ip, l.taskID, err)
			}
		}
	}
	for _, d := range dead { // audit every expiry, shared or not
		l.audit("dns:expire", map[string]interface{}{
			"domain": d.domain, "ip": d.e.ip, "expiry": d.e.expiry.UTC().Format(time.RFC3339),
		}, fmt.Sprintf("TTL expired for %s -> %s", d.domain, d.e.ip))
	}
}

// Close stops the sweeper and the DNS proxy and waits for their goroutines.
// Idempotent. Does NOT unregister the learner (the owner decides when the
// task's API surface disappears) and does NOT flush the whitelist map — the
// map's lifecycle belongs to network.DetachTaskFilter.
func (l *Learner) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	cancel := l.cancel
	proxy := l.proxy
	l.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if proxy != nil {
		proxy.Close()
	}
	l.wg.Wait()
	return nil
}

// audit appends a best-effort record to the task's ledger. Learning is
// advisory: an audit failure is logged, never fatal — a full disk must not
// blackhole the guest's DNS.
func (l *Learner) audit(action string, params map[string]interface{}, reason string) {
	if l.ledger == nil {
		return
	}
	if err := l.ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  "dnslearn",
		Action:   action,
		Params:   params,
		Decision: audit.DecisionAllow,
		Reason:   reason,
	}); err != nil {
		log.Printf("dnslearn: audit %s for task %s failed: %v", action, l.taskID, err)
	}
}

// AuditDegraded records a security:degraded_warning (same action string the
// container manager uses for the TC-filter and jail degraded modes).
func (l *Learner) AuditDegraded(reason string) {
	l.audit("security:degraded_warning", map[string]interface{}{"task": l.taskID}, reason)
}

// --- process-local learner registry -------------------------------------
//
// The registry keys live learners by task id so the REST API
// (internal/api) and the egress gateway's rebinding guard can reach the
// learner StartTask created, without the container package exporting
// per-task internals. It is process-local like the policy-gateway registry
// in internal/api: `agentpvm run` and its API share one process.

var registry = struct {
	sync.RWMutex
	m map[string]*Learner
}{m: map[string]*Learner{}}

// Register publishes l under its task id, replacing any previous learner
// (the replaced one is NOT closed — its owner keeps that responsibility).
func Register(l *Learner) {
	registry.Lock()
	defer registry.Unlock()
	registry.m[l.taskID] = l
}

// GetOrCreate atomically returns the registered learner for taskID, or
// calls new (outside the registry lock, so new may itself touch the
// registry) and registers it. When two callers race, both learners exist
// but only the winner is published; the loser's learner is closed by the
// caller-provided new's owner responsibility here — GetOrCreate closes the
// loser before returning it, so callers never leak a bound UDP socket or
// sweeper goroutine. This is the only race-free construction path for the
// API's control-plane learners (PUT policy + POST allow can race).
func GetOrCreate(taskID string, new func() (*Learner, error)) (*Learner, error) {
	if l := For(taskID); l != nil {
		return l, nil
	}
	l, err := new()
	if err != nil {
		return nil, err
	}
	registry.Lock()
	winner, race := registry.m[taskID]
	if !race {
		registry.m[taskID] = l
	}
	registry.Unlock()
	if race {
		_ = l.Close() // lost the race: the winner stays registered
		return winner, nil
	}
	return l, nil
}

// Unregister removes the learner for taskID if (and only if) it is l, so a
// late teardown cannot evict a newer learner for a reused task id.
func Unregister(taskID string, l *Learner) {
	registry.Lock()
	defer registry.Unlock()
	if registry.m[taskID] == l {
		delete(registry.m, taskID)
	}
}

// For returns the registered learner for taskID, or nil.
func For(taskID string) *Learner {
	registry.RLock()
	defer registry.RUnlock()
	return registry.m[taskID]
}

// Checker adapts the registry to egress.LearnedIPChecker: the live
// DNS-learned IP set for a (task, host) pair, nil when the task has no
// learner or the host was never learned (fail-open for unlearned hosts).
type Checker struct{}

// LearnedIPs implements egress.LearnedIPChecker.
func (Checker) LearnedIPs(task, host string) []net.IP {
	l := For(task)
	if l == nil {
		return nil
	}
	return l.LearnedIPs(host)
}
