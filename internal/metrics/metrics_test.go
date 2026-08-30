package metrics

import (
	"fmt"
	"strings"
	"testing"
)

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
