package api

// DNS-learned egress endpoints (todo.md P1-B). The learners themselves are
// created by container.StartTask when a spec sets network.dns_learn_enabled
// and published through the process-local dnslearn registry; these handlers
// expose them over REST and can also create a control-plane learner on
// demand (PUT policy / POST allow) so the API can drive learning without a
// live task — that on-demand path binds loopback-only and uses a NopWriter
// (table-only; no eBPF map is reachable from this process context).

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"

	"uml-container/internal/audit"
	"uml-container/internal/network/dnslearn"
	"uml-container/internal/spec"

	"github.com/labstack/echo/v4"
)

// dnsDomainRegex guards caller-supplied domains before they enter the
// allowlist: letters/digits/dots/hyphens plus one leading "*." wildcard.
// It deliberately excludes ':' and '/' so a "domain" can never smuggle a
// URL or host:port into the policy plane.
var dnsDomainRegex = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)

// dnsPolicyRequest is the PUT /egress/:task/policy body. Nil/empty fields
// mean "leave unchanged" on a live learner.
type dnsPolicyRequest struct {
	DNSLearnEnabled   *bool    `json:"dns_learn_enabled"`
	LearnTTL          string   `json:"learn_ttl"`
	DNSUpstream       string   `json:"dns_upstream"`
	MaxLearnedEntries int      `json:"max_learned_entries"`
	AllowDomains      []string `json:"allow_domains"`
}

// dnsPolicyView renders a learner's runtime state.
func dnsPolicyView(l *dnslearn.Learner) map[string]interface{} {
	return map[string]interface{}{
		"task":                l.TaskID(),
		"dns_learn_enabled":   l.Enabled(),
		"learn_ttl":           l.LearnTTL().String(),
		"dns_upstream":        l.Upstream(),
		"dns_addr":            l.Addr(),
		"max_learned_entries": maxEntriesForView(l),
		"entries":             l.Count(),
		"dropped":             l.Dropped(),
		"allow_domains":       l.AllowList(),
	}
}

// maxEntriesForView exposes the cap without adding a getter just for the API.
func maxEntriesForView(l *dnslearn.Learner) int { return l.MaxEntries() }

// ensureDNSLearner returns the registered learner for taskID, creating a
// control-plane one when absent. Control-plane learners are table-only
// (NopWriter: no per-task eBPF map is reachable here) and bind their DNS
// proxy on a loopback ephemeral port; they exist so learn mode can be
// driven/tested through the API without a running task. The whole
// check-create-register runs through dnslearn.GetOrCreate so concurrent
// PUT policy / POST allow calls cannot leak a learner (the loser is
// closed inside GetOrCreate).
func ensureDNSLearner(taskID string, req *dnsPolicyRequest) (*dnslearn.Learner, error) {
	return dnslearn.GetOrCreate(taskID, func() (*dnslearn.Learner, error) {
		ledger, err := audit.Open(taskID)
		if err != nil {
			return nil, fmt.Errorf("open ledger: %w", err)
		}
		cfg := dnslearn.Config{
			TaskID: taskID,
			Ledger: ledger,
			Writer: dnslearn.NopWriter{},
		}
		if req != nil {
			cfg.Upstream = req.DNSUpstream
			cfg.AllowDomains = req.AllowDomains
			cfg.MaxEntries = req.MaxLearnedEntries
			if req.LearnTTL != "" {
				d, err := time.ParseDuration(req.LearnTTL)
				if err != nil || d <= 0 {
					return nil, fmt.Errorf("learn_ttl %q: must be a positive Go duration", req.LearnTTL)
				}
				cfg.LearnTTL = d
			}
		}
		if cfg.MaxEntries < 0 || cfg.MaxEntries > spec.MaxLearnedEntriesLimit {
			return nil, fmt.Errorf("max_learned_entries %d out of range (0..%d)",
				cfg.MaxEntries, spec.MaxLearnedEntriesLimit)
		}
		l, err := dnslearn.New(cfg)
		if err != nil {
			return nil, err
		}
		if req != nil && req.DNSLearnEnabled != nil {
			l.SetEnabled(*req.DNSLearnEnabled)
		}
		// The loopback bind can still fail (fd exhaustion); learning then
		// continues via promote/LearnNow only, with evidence.
		ctx := context.Background()
		l.Run(ctx)
		if _, err := l.StartProxy(ctx, "127.0.0.1:0"); err != nil {
			l.AuditDegraded(fmt.Sprintf("control-plane dns proxy bind failed: %v", err))
		}
		return l, nil
	})
}

// registerDNSEgressRoutes wires the P1-B DNS-learned egress endpoints.
// Called from NewE2BServer; all routes sit behind the /api Bearer auth.
// dnsTaskLocks serializes learner lifecycle transitions per task id.
// The registry itself only guards the map; without this lock a DELETE
// (Unregister then Close) races a concurrent POST allow / PUT policy
// creating a replacement learner in between — DELETE would report
// success while the task ends up with a live learner again.
var dnsTaskLocks = struct {
	sync.Mutex
	m map[string]*sync.Mutex
}{m: map[string]*sync.Mutex{}}

func dnsTaskLock(taskID string) *sync.Mutex {
	dnsTaskLocks.Lock()
	defer dnsTaskLocks.Unlock()
	mu := dnsTaskLocks.m[taskID]
	if mu == nil {
		mu = &sync.Mutex{}
		dnsTaskLocks.m[taskID] = mu
	}
	return mu
}

func registerDNSEgressRoutes(api *echo.Group) {
	// Live learned set with expiries.
	api.GET("/egress/:task/learned", func(c echo.Context) error {
		task := c.Param("task")
		if !idRegex.MatchString(task) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		l := dnslearn.For(task)
		if l == nil {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "no DNS learner registered for task (dns_learn_enabled off or task not running)",
			})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"task":    task,
			"entries": l.List(),
		})
	})

	// Promote: add a domain to the task's runtime allowlist and learn its
	// current resolution immediately (best-effort — an unreachable upstream
	// does not fail the promote).
	api.POST("/egress/:task/allow", func(c echo.Context) error {
		task := c.Param("task")
		if !idRegex.MatchString(task) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		mu := dnsTaskLock(task)
		mu.Lock()
		defer mu.Unlock()
		var body struct {
			Domain string `json:"domain"`
		}
		if err := c.Bind(&body); err != nil || !dnsDomainRegex.MatchString(body.Domain) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or missing domain"})
		}
		l, err := ensureDNSLearner(task, nil)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		fresh := l.AddAllow(body.Domain)
		resp := map[string]interface{}{
			"task":               task,
			"domain":             body.Domain,
			"added_to_allowlist": fresh,
			"learned":            0,
		}
		if n, lerr := l.LearnNow(body.Domain); lerr != nil {
			resp["learn_error"] = lerr.Error()
		} else {
			resp["learned"] = n
		}
		return c.JSON(http.StatusOK, resp)
	})

	// Drop learned entries for one host (table + whitelist map).
	api.DELETE("/egress/:task/learned/:host", func(c echo.Context) error {
		task := c.Param("task")
		if !idRegex.MatchString(task) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		l := dnslearn.For(task)
		if l == nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no DNS learner registered for task"})
		}
		host := c.Param("host")
		if !dnsDomainRegex.MatchString(host) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid host"})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"task":    task,
			"host":    host,
			"dropped": l.Drop(host),
		})
	})

	// Read the learn-mode policy of a task.
	api.GET("/egress/:task/policy", func(c echo.Context) error {
		task := c.Param("task")
		if !idRegex.MatchString(task) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		l := dnslearn.For(task)
		if l == nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no DNS learner registered for task"})
		}
		return c.JSON(http.StatusOK, dnsPolicyView(l))
	})

	// Toggle learn mode / TTL. Without a live learner, enabling creates a
	// control-plane learner (see ensureDNSLearner); a bare "enabled:false"
	// PUT against a task that never learned is a 404, not a silent create.
	api.PUT("/egress/:task/policy", func(c echo.Context) error {
		task := c.Param("task")
		if !idRegex.MatchString(task) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		mu := dnsTaskLock(task)
		mu.Lock()
		defer mu.Unlock()
		var req dnsPolicyRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
		}
		l := dnslearn.For(task)
		if l == nil {
			if req.DNSLearnEnabled == nil || !*req.DNSLearnEnabled {
				return c.JSON(http.StatusNotFound, map[string]string{
					"error": "no DNS learner registered for task; create one with dns_learn_enabled=true",
				})
			}
			var err error
			l, err = ensureDNSLearner(task, &req)
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusOK, dnsPolicyView(l))
		}
		// Live learner: upstream and the entry cap are creation-time
		// parameters (changing the upstream would require rebinding the
		// proxy); refuse silently-dropped changes.
		if req.DNSUpstream != "" && req.DNSUpstream != l.Upstream() {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "dns_upstream is fixed at learner creation",
			})
		}
		if req.MaxLearnedEntries != 0 && req.MaxLearnedEntries != l.MaxEntries() {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "max_learned_entries is fixed at learner creation",
			})
		}
		if req.LearnTTL != "" {
			d, err := time.ParseDuration(req.LearnTTL)
			if err != nil || d <= 0 {
				return c.JSON(http.StatusBadRequest, map[string]string{
					"error": fmt.Sprintf("learn_ttl %q: must be a positive Go duration", req.LearnTTL),
				})
			}
			l.SetLearnTTL(d)
		}
		if req.DNSLearnEnabled != nil {
			l.SetEnabled(*req.DNSLearnEnabled)
		}
		for _, d := range req.AllowDomains {
			if !dnsDomainRegex.MatchString(d) {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid domain " + d})
			}
			l.AddAllow(d)
		}
		return c.JSON(http.StatusOK, dnsPolicyView(l))
	})

	// Release path for control-plane learners (review: every PUT with a new
	// task id pinned a sweeper goroutine, a UDP socket and an open ledger
	// forever). DELETE closes the learner and unregisters it; live task
	// learners are ALSO deletable — StartTask's teardown tolerates a missing
	// learner, and removing one early only stops learning (the L7 proxy and
	// the BPF floor keep enforcing).
	api.DELETE("/egress/:task/policy", func(c echo.Context) error {
		task := c.Param("task")
		if !idRegex.MatchString(task) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		// Held across Unregister AND Close: without the lock a concurrent
		// POST allow could register a replacement learner between the two
		// and this handler would return "deleted" for a task that ends up
		// with a live learner.
		mu := dnsTaskLock(task)
		mu.Lock()
		defer mu.Unlock()
		l := dnslearn.For(task)
		if l == nil {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "no DNS learner registered for task",
			})
		}
		dnslearn.Unregister(task, l)
		if err := l.Close(); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"task":    task,
			"deleted": true,
		})
	})
}
