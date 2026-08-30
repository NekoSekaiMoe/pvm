package metrics

import (
	"fmt"
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

// TestSeriesCardinalityCapped guards the PR #22 review finding: per-task
// labels must not grow the registry (and every /metrics scrape) without
// bound. New combinations beyond defaultMaxCardinality are dropped.
func TestSeriesCardinalityCapped(t *testing.T) {
	c := Counter("pvm_test_cardinality_total", "cardinality cap regression test", "task")
	for i := 0; i < defaultMaxCardinality+500; i++ {
		c.Inc(fmt.Sprintf("task-%d", i))
	}
	rendered := Default().Render()
	lines := strings.Count(rendered, "pvm_test_cardinality_total{")
	if lines > defaultMaxCardinality {
		t.Fatalf("series rendered %d label combinations, cap is %d", lines, defaultMaxCardinality)
	}
}

// TestCounterDelete exercises the cleanup entry point task owners use when a
// task ends (see watchdog killTask).
func TestCounterDelete(t *testing.T) {
	c := Counter("pvm_test_delete_total", "delete regression test", "task")
	c.Inc("doomed")
	if !strings.Contains(Default().Render(), `pvm_test_delete_total{task="doomed"} 1`) {
		t.Fatal("series must render before delete")
	}
	c.Delete("doomed")
	if strings.Contains(Default().Render(), `task="doomed"`) {
		t.Fatal("deleted label combination must not render")
	}
	// Deleting again is a no-op; re-Inc after Delete starts fresh at 1.
	c.Delete("doomed")
	c.Inc("doomed")
	if !strings.Contains(Default().Render(), `pvm_test_delete_total{task="doomed"} 1`) {
		t.Fatal("re-Inc after Delete must start from zero")
	}
}
