package api

import (
	"strings"
	"testing"

	"uml-container/internal/metrics"
	"uml-container/internal/state"
)

func TestParseProcStatCPU(t *testing.T) {
	cases := []struct {
		name string
		stat string
		want float64
	}{
		// comm with spaces + parens must not break field indexing.
		{"spaces and parens in comm", "1234 (my (uml) proc) R 1 2 3 4 5 6 7 0 0 0 100 200 0 0 20 0 1 0", 3},
		{"garbage is zero", "garbage", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseProcStatCPU(tc.stat); got != tc.want {
				t.Fatalf("parseProcStatCPU = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseProcStatmRSS(t *testing.T) {
	cases := []struct {
		name  string
		statm string
		zero  bool // expect 0
	}{
		{"pages times pagesize", "1234 567 89 0 0 0 0", false},
		{"garbage is zero", "x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseProcStatmRSS(tc.statm)
			if tc.zero {
				if got != 0 {
					t.Fatalf("parseProcStatmRSS(%q) = %v, want 0", tc.statm, got)
				}
				return
			}
			if got <= 0 || int(got)%4096 != 0 && int(got)%osPageSize() != 0 {
				t.Fatalf("rss = %v, want pages*pagesize", got)
			}
		})
	}
}

func osPageSize() int { return 4096 }

func TestCollectorsRenderHookWired(t *testing.T) {
	registerResourceCollectors()
	out := metrics.Default().Render()
	for _, name := range []string{"pvm_tasks", "pvm_task_cpu_seconds_total", "pvm_task_memory_rss_bytes", "pvm_templates", "pvm_volumes"} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(out, name) {
				t.Fatalf("render missing %s:\n%s", name, out)
			}
		})
	}
}

// A state label whose last task left must drop to 0, not linger at its
// last non-zero value (the collectTaskGauges doc comment always claimed
// this; the code only learned it here).
func TestCollectTaskGaugesZeroesStaleStates(t *testing.T) {
	// t.TempDir dies at test end; later tests must not read the stale
	// state root.
	old := state.RootDir
	t.Cleanup(func() { state.RootDir = old })
	state.RootDir = t.TempDir() // no tasks at all
	tasksByState.Set(3, "running")
	collectTaskGauges()
	out := metrics.Default().Render()
	if !strings.Contains(out, `pvm_tasks{state="running"} 0`) {
		t.Fatalf("stale state label not zeroed:\n%s", out)
	}
}

// A template status whose last template left must drop to 0 too —
// pvm_templates{status=X} must not linger at its last non-zero value
// after the final X template is deleted (mirrors the task behavior).
func TestCollectInventoryGaugesZeroesStaleTemplateStates(t *testing.T) {
	cases := []struct {
		name    string
		tmplEnv string  // PVM_TEMPLATE_ROOT ("" = a fresh empty dir: no templates)
		setVal  float64 // stale gauge value planted for the status label
		status  string
		want    string // expected zeroed render line
	}{
		{
			name:    "no templates zeroes READY",
			tmplEnv: "",
			setVal:  2,
			status:  "READY",
			want:    `pvm_templates{status="READY"} 0`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.tmplEnv
			if root == "" {
				root = t.TempDir() // no templates at all
			}
			t.Setenv("PVM_TEMPLATE_ROOT", root)
			tmplGauge.Set(tc.setVal, tc.status)
			collectInventoryGauges()
			out := metrics.Default().Render()
			if !strings.Contains(out, tc.want) {
				t.Fatalf("stale template status label not zeroed:\n%s", out)
			}
		})
	}
}
