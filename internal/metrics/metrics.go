// Package metrics is a tiny, dependency-free Prometheus-style metrics
// registry. Counters and gauges are created lazily, kept in a process-global
// registry, and rendered in the Prometheus text exposition format on demand.
//
// The API server exposes the render output at GET /metrics; egress, incident,
// audit and lifecycle code paths Inc/Add/Set series from their own packages
// without importing echo (no import cycles: this package imports nothing but
// the standard library).
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type seriesKind int

const (
	kindCounter seriesKind = iota
	kindGauge
)

type series struct {
	name   string
	help   string
	kind   seriesKind
	labels []string

	mu     sync.Mutex
	values map[string]float64 // rendered label values joined by \xff
}

// defaultMaxCardinality bounds the number of distinct label combinations per
// series. Unbounded label values (task ids, hosts, ...) would otherwise grow
// the registry — and every /metrics scrape — linearly with task churn until
// the process restarts. Series should still call Delete on cleanup; the cap
// is the safety net, not the policy.
const defaultMaxCardinality = 4096

// Registry holds every series created through it. The package-level default
// registry is what /metrics renders; NewRegistry exists for tests.
type Registry struct {
	mu      sync.Mutex
	series  map[string]*series
	started time.Time
}

var defaultRegistry = &Registry{series: map[string]*series{}, started: time.Now()}

// Default returns the process-global registry.
func Default() *Registry { return defaultRegistry }

func (r *Registry) get(name, help string, kind seriesKind, labels []string) *series {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.series[name]
	if !ok {
		s = &series{name: name, help: help, kind: kind, labels: append([]string(nil), labels...), values: map[string]float64{}}
		r.series[name] = s
	}
	// A second get with different help/labels is a programming error; keep
	// the first registration and ignore later metadata mismatches rather
	// than panicking inside a request path.
	return s
}

func (s *series) key(labelValues []string) string {
	return strings.Join(labelValues, "\xff")
}

func (s *series) add(delta float64, labelValues []string) {
	if len(labelValues) != len(s.labels) {
		// Never panic on label arity bugs in hot paths; drop the sample.
		return
	}
	s.mu.Lock()
	s.boundedAdd(delta, labelValues)
	s.mu.Unlock()
}

// boundedAdd inserts (or updates) a sample while holding s.mu. NEW label
// combinations beyond defaultMaxCardinality are dropped: counters keep
// serving existing series and memory stays bounded.
func (s *series) boundedAdd(delta float64, labelValues []string) {
	k := s.key(labelValues)
	if _, ok := s.values[k]; !ok && len(s.values) >= defaultMaxCardinality {
		return
	}
	s.values[k] += delta
}

func (s *series) set(v float64, labelValues []string) {
	if len(labelValues) != len(s.labels) {
		return
	}
	s.mu.Lock()
	k := s.key(labelValues)
	if _, ok := s.values[k]; !ok && len(s.values) >= defaultMaxCardinality {
		s.mu.Unlock()
		return
	}
	s.values[k] = v
	s.mu.Unlock()
}

func (s *series) delete(labelValues []string) {
	if len(labelValues) != len(s.labels) {
		return
	}
	s.mu.Lock()
	delete(s.values, s.key(labelValues))
	s.mu.Unlock()
}

// CounterHandle is a handle to a counter series. labelValues order
// must match labels on every call.
type CounterHandle struct{ s *series }

// Inc adds 1 for the given label values.
func (c CounterHandle) Inc(labelValues ...string) { c.s.add(1, labelValues) }

// Add adds delta for the given label values.
func (c CounterHandle) Add(delta float64, labelValues ...string) { c.s.add(delta, labelValues) }

// Delete removes a label combination (call when the labeled task ends so
// per-task series do not accumulate for the process lifetime).
func (c CounterHandle) Delete(labelValues ...string) { c.s.delete(labelValues) }

// GaugeHandle is a handle to a gauge series.
type GaugeHandle struct{ s *series }

// Set stores v for the given label values.
func (g GaugeHandle) Set(v float64, labelValues ...string) { g.s.set(v, labelValues) }

// Labels snapshots the current label-value tuples (one entry per series
// row). Collectors use it to find stale rows to Delete.
func (g GaugeHandle) Labels() [][]string {
	g.s.mu.Lock()
	defer g.s.mu.Unlock()
	out := make([][]string, 0, len(g.s.values))
	for k := range g.s.values {
		if len(g.s.labels) == 0 {
			// Unlabeled series: the key is "", and Split would wrongly
			// yield a one-empty-string tuple instead of the empty one.
			out = append(out, []string{})
			continue
		}
		out = append(out, strings.Split(k, "\xff"))
	}
	return out
}

// Delete removes a label combination (call when the labeled task ends).
func (g GaugeHandle) Delete(labelValues ...string) { g.s.delete(labelValues) }

// Counter declares (or fetches) a counter on the default registry.
func Counter(name, help string, labels ...string) CounterHandle {
	return CounterHandle{defaultRegistry.get(name, help, kindCounter, labels)}
}

// Gauge declares (or fetches) a gauge on the default registry.
func Gauge(name, help string, labels ...string) GaugeHandle {
	return GaugeHandle{defaultRegistry.get(name, help, kindGauge, labels)}
}

// Uptime returns how long the registry (process) has been running.
func Uptime() time.Duration { return time.Since(defaultRegistry.started) }

// renderHooks are invoked at the top of every Render: they refresh gauge
// values whose source of truth lives elsewhere (task states, /proc, pool
// stats). A panicking hook is recovered and skipped — a broken collector
// must never take down /metrics.
var (
	renderHooksMu sync.Mutex
	renderHooks   []func()
)

// OnRender registers a refresh callback run at the start of Render.
func OnRender(fn func()) {
	renderHooksMu.Lock()
	renderHooks = append(renderHooks, fn)
	renderHooksMu.Unlock()
}

func runRenderHooks() {
	renderHooksMu.Lock()
	fns := append([]func(){}, renderHooks...)
	renderHooksMu.Unlock()
	for _, fn := range fns {
		if fn == nil {
			continue
		}
		func() {
			defer func() { _ = recover() }()
			fn()
		}()
	}
}

// Render produces the Prometheus text exposition format for every series in
// the registry, in stable (name, labels) order.
func (r *Registry) Render() string {
	runRenderHooks()
	r.mu.Lock()
	names := make([]string, 0, len(r.series))
	for n := range r.series {
		names = append(names, n)
	}
	sort.Strings(names)
	snapshot := make([]*series, 0, len(names))
	for _, n := range names {
		snapshot = append(snapshot, r.series[n])
	}
	r.mu.Unlock()

	var b strings.Builder
	for _, s := range snapshot {
		typ := "counter"
		if s.kind == kindGauge {
			typ = "gauge"
		}
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", s.name, s.help, s.name, typ)
		s.mu.Lock()
		keys := make([]string, 0, len(s.values))
		for k := range s.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lvs := strings.Split(k, "\xff")
			if len(s.labels) == 0 {
				fmt.Fprintf(&b, "%s %v\n", s.name, formatFloat(s.values[k]))
				continue
			}
			pairs := make([]string, 0, len(s.labels))
			for i, ln := range s.labels {
				pairs = append(pairs, fmt.Sprintf("%s=%q", ln, lvs[i]))
			}
			fmt.Fprintf(&b, "%s{%s} %v\n", s.name, strings.Join(pairs, ","), formatFloat(s.values[k]))
		}
		s.mu.Unlock()
	}
	fmt.Fprintf(&b, "# HELP pvm_uptime_seconds Process uptime in seconds\n# TYPE pvm_uptime_seconds gauge\npvm_uptime_seconds %v\n", int(Uptime().Seconds()))
	return b.String()
}

func formatFloat(v float64) string {
	// Prometheus accepts fixed or scientific notation; keep integers clean.
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
