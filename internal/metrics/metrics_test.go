package metrics

import (
	"strings"
	"testing"
	"time"
)

func newTestRegistry() *Registry {
	return &Registry{series: map[string]*series{}, started: time.Now()}
}

func TestCounterGaugeRender(t *testing.T) {
	r := newTestRegistry()
	prev := defaultRegistry
	defaultRegistry = r
	defer func() { defaultRegistry = prev }()

	c := Counter("pvm_test_total", "test counter", "task")
	c.Inc("a")
	c.Add(2, "a")
	g := Gauge("pvm_test_gauge", "test gauge")
	g.Set(1.5)
	out := r.Render()
	for _, want := range []string{
		"# TYPE pvm_test_total counter",
		`pvm_test_total{task="a"} 3`,
		"# TYPE pvm_test_gauge gauge",
		"pvm_test_gauge 1.5",
		"pvm_uptime_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q:\n%s", want, out)
		}
	}
}

func TestLabelArityMismatchDropped(t *testing.T) {
	r := newTestRegistry()
	prev := defaultRegistry
	defaultRegistry = r
	defer func() { defaultRegistry = prev }()

	c := Counter("pvm_arity_total", "arity", "a", "b")
	c.Inc("only-one") // wrong arity: must be dropped, not panic
	if out := r.Render(); strings.Contains(out, "pvm_arity_total{") {
		t.Fatal("wrong-arity sample must not be recorded")
	}
}

func TestSameSeriesSecondDeclareReuses(t *testing.T) {
	r := newTestRegistry()
	prev := defaultRegistry
	defaultRegistry = r
	defer func() { defaultRegistry = prev }()

	Counter("pvm_dup_total", "first help").Inc()
	Counter("pvm_dup_total", "different help").Inc()
	out := r.Render()
	if got := strings.Count(out, "pvm_dup_total"); got < 2 { // HELP+TYPE+sample lines
		t.Fatalf("expected samples recorded, got:\n%s", out)
	}
	if !strings.Contains(out, "pvm_dup_total 2") {
		t.Fatalf("counter must accumulate across re-declares:\n%s", out)
	}
}
