package api

import (
	"strings"
	"testing"

	"uml-container/internal/metrics"
)

func TestParseProcStatCPU(t *testing.T) {
	// comm with spaces + parens must not break field indexing.
	stat := "1234 (my (uml) proc) R 1 2 3 4 5 6 7 0 0 0 100 200 0 0 20 0 1 0"
	if got := parseProcStatCPU(stat); got != 3 {
		t.Fatalf("cpu = %v, want 3 (100+200 ticks / 100Hz)", got)
	}
	if got := parseProcStatCPU("garbage"); got != 0 {
		t.Fatalf("garbage = %v, want 0", got)
	}
}

func TestParseProcStatmRSS(t *testing.T) {
	got := parseProcStatmRSS("1234 567 89 0 0 0 0")
	if got <= 0 || int(got)%4096 != 0 && int(got)%osPageSize() != 0 {
		t.Fatalf("rss = %v, want pages*pagesize", got)
	}
	if got := parseProcStatmRSS("x"); got != 0 {
		t.Fatalf("garbage = %v, want 0", got)
	}
}

func osPageSize() int { return 4096 }

func TestCollectorsRenderHookWired(t *testing.T) {
	registerResourceCollectors()
	out := metrics.Default().Render()
	for _, name := range []string{"pvm_tasks", "pvm_task_cpu_seconds_total", "pvm_task_memory_rss_bytes", "pvm_templates", "pvm_volumes"} {
		if !strings.Contains(out, name) {
			t.Fatalf("render missing %s:\n%s", name, out)
		}
	}
}
