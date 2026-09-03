package api

// collectors.go — host-side resource collectors for /metrics.
//
// Every gauge here is refreshed by a render hook (metrics.OnRender) at
// scrape time, so the values are always as fresh as the last scrape and
// cost nothing while nobody is watching. Sources:
//
//   - task inventory + FSM state    → state.ListAll()
//   - per-task host process usage   → /proc/<pid>/stat, /proc/<pid>/statm
//     (the UML monitor process IS the sandbox from the host's point of
//     view: its CPU time and RSS bound the whole guest — the
//     "host_sandbox" view)
//   - template / volume inventory   → template + volume stores
//
// The guest-internal ("guest_workload") view is intentionally NOT sampled
// here: it would require running a collector inside each guest. Per-task
// API metrics (GET /api/tasks/:id/metrics) remain the per-task surface.

import (
	"os"
	"strconv"
	"strings"
	"sync"

	"uml-container/internal/metrics"
	"uml-container/internal/state"
	"uml-container/internal/template"
	"uml-container/internal/volume"
)

var (
	tasksByState = metrics.Gauge("pvm_tasks", "Tasks by FSM state", "state")
	taskCPUGauge = metrics.Gauge("pvm_task_cpu_seconds_total", "Host CPU seconds consumed by the task's UML process (host_sandbox view)", "task")
	taskRSSGauge = metrics.Gauge("pvm_task_memory_rss_bytes", "Resident memory of the task's UML process in bytes (host_sandbox view)", "task")
	tmplGauge    = metrics.Gauge("pvm_templates", "Templates by status", "status")
	volGauge     = metrics.Gauge("pvm_volumes", "Persistent volumes registered in the store")

	collectorsOnce sync.Once
)

// registerResourceCollectors installs the render hooks exactly once.
func registerResourceCollectors() {
	collectorsOnce.Do(func() {
		metrics.OnRender(collectTaskGauges)
		metrics.OnRender(collectInventoryGauges)
	})
}

// collectTaskGauges refreshes pvm_tasks{state} and the per-task process
// gauges. Stale per-task labels (task gone or process exited) are deleted
// so the series does not linger at its last value.
func collectTaskGauges() {
	all, err := state.ListAll()
	if err != nil {
		return
	}
	byState := make(map[string]int)
	seen := make(map[string]bool, len(all))
	for _, st := range all {
		byState[string(st.Status)]++
		seen[st.ID] = true
		if st.PID > 0 {
			cpu, rss := procUsage(st.PID)
			taskCPUGauge.Set(cpu, st.ID)
			taskRSSGauge.Set(rss, st.ID)
		}
	}
	// Refresh every currently-present state label...
	for s, n := range byState {
		tasksByState.Set(float64(n), s)
	}
	// ...and zero the ones whose last task left: without this, a state
	// label lingers at its last non-zero value forever (the doc comment
	// always claimed it; the code never did).
	for _, lvs := range tasksByState.Labels() {
		if len(lvs) == 1 {
			if _, still := byState[lvs[0]]; !still {
				tasksByState.Set(0, lvs[0])
			}
		}
	}
	// Drop per-task labels whose task disappeared.
	for _, lvs := range taskCPUGauge.Labels() {
		if len(lvs) == 1 && !seen[lvs[0]] {
			taskCPUGauge.Delete(lvs[0])
			taskRSSGauge.Delete(lvs[0])
		}
	}
}

// collectInventoryGauges refreshes template and volume counts.
func collectInventoryGauges() {
	if list, err := (template.NewStore("")).List(); err == nil {
		byStatus := make(map[string]int)
		for _, rec := range list {
			byStatus[rec.Status]++
		}
		for s, n := range byStatus {
			tmplGauge.Set(float64(n), s)
		}
	}
	if vols, err := volume.NewStore("").List(); err == nil {
		volGauge.Set(float64(len(vols)))
	} else {
		// Fall back to the cow-engine-root view used by /api/volumes.
		volGauge.Set(0)
	}
}

// procUsage reads the process's cumulative CPU seconds and current RSS
// bytes. Missing/exited processes report zeros (callers keep the label so
// the disappearance is visible as a 0 before the next cleanup pass).
func procUsage(pid int) (cpuSeconds, rssBytes float64) {
	if data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		cpuSeconds = parseProcStatCPU(string(data))
	}
	if data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm"); err == nil {
		rssBytes = parseProcStatmRSS(string(data))
	}
	return
}

// parseProcStatCPU sums utime+stime (fields 14+15, clock ticks) and
// converts to seconds using the ubiquitous 100 Hz assumption (Linux has
// hard-coded USER_HZ=100 on every arch PVM supports).
func parseProcStatCPU(stat string) float64 {
	// Fields after the comm field (which is parenthesized and may contain
	// spaces): find the last ')' and split the rest.
	idx := strings.LastIndex(stat, ")")
	if idx < 0 || idx+2 > len(stat) {
		return 0
	}
	fields := strings.Fields(stat[idx+2:])
	// fields[0] is state (field 3); utime is field 14 → index 11.
	if len(fields) < 13 {
		return 0
	}
	utime, err1 := strconv.ParseFloat(fields[11], 64)
	stime, err2 := strconv.ParseFloat(fields[12], 64)
	if err1 != nil || err2 != nil {
		return 0
	}
	return (utime + stime) / 100.0
}

// parseProcStatmRSS reads the second field of statm (resident pages) and
// converts to bytes using the page size read at process start.
func parseProcStatmRSS(statm string) float64 {
	fields := strings.Fields(statm)
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0
	}
	return pages * float64(os.Getpagesize())
}
