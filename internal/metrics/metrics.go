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
	s.values[s.key(labelValues)] += delta
	s.mu.Unlock()
}

func (s *series) set(v float64, labelValues []string) {
	if len(labelValues) != len(s.labels) {
		return
	}
	s.mu.Lock()
	s.values[s.key(labelValues)] = v
	s.mu.Unlock()
}

// CounterHandle is a handle to a counter series. labelValues order
// must match labels on every call.
type CounterHandle struct{ s *series }

// Inc adds 1 for the given label values.
func (c CounterHandle) Inc(labelValues ...string) { c.s.add(1, labelValues) }

// Add adds delta for the given label values.
func (c CounterHandle) Add(delta float64, labelValues ...string) { c.s.add(delta, labelValues) }

// GaugeHandle is a handle to a gauge series.
type GaugeHandle struct{ s *series }

// Set stores v for the given label values.
func (g GaugeHandle) Set(v float64, labelValues ...string) { g.s.set(v, labelValues) }

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

// Render produces the Prometheus text exposition format for every series in
// the registry, in stable (name, labels) order.
func (r *Registry) Render() string {
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
