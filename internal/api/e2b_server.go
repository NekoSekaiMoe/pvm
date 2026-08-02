package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"uml-container/internal/approval"
	"uml-container/internal/artifact"
	"uml-container/internal/audit"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/image"
	"uml-container/internal/policy"
	"uml-container/internal/pool"
	"uml-container/internal/snapshot"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/webui"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type ExecRequest struct {
	Command string `json:"cmd"`
}

type ExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

// StartE2BServer starts a REST API compatible with E2B SDK and serves the WebUI
func StartE2BServer(port int) error {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000", "http://127.0.0.1:3000"},
	}))

	// API Group
	api := e.Group("/api")
	api.Use(middleware.KeyAuth(func(key string, c echo.Context) (bool, error) {
		expected := os.Getenv("API_SECRET")
		if expected == "" {
			expected = "secret"
		}
		return key == expected, nil
	}))

	// Per-task policy gateways registered by the controller / agentpvm run.
	// /api/exec and /api/policy/:task both read from the SAME global registry
	// (RegisterPolicyGateway writes here too), so a gateway registered by
	// agentpvm run is visible to /api/exec without an extra wiring step.
	gateways := globalRegistries

	// Get all containers
	api.GET("/containers", func(c echo.Context) error {
		list, err := state.ListAll()
		if err != nil {
			return c.JSON(http.StatusOK, []interface{}{})
		}
		return c.JSON(http.StatusOK, list)
	})

	// Start a container via shelling out to umlctl to ensure proper isolation
	api.POST("/containers/start", func(c echo.Context) error {
		type StartReq struct {
			Name   string `json:"name"`
			Rootfs string `json:"rootfs"`
			Mem    string `json:"mem"`
			CPU    int    `json:"cpu"`
		}
		var req StartReq
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.Name == "" {
			req.Name = "web-container"
		}

		if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(req.Name) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid container ID format"})
		}
		if req.CPU < 0 || req.CPU > 1024 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "CPU limit must be between 0 and 1024"})
		}

		mgr := container.NewManager(nil)
		mem := req.Mem
		if mem == "" {
			mem = "512M"
		}
		memBytes, err := config.ParseMemory(mem)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		cfg := &config.ContainerConfig{
			ID:          req.Name,
			Name:        req.Name,
			Rootfs:      req.Rootfs,
			Kernel:      "./bin/linux",
			Init:        "/init.sh",
			Memory:      mem,
			MemoryBytes: memBytes,
			CPU:         req.CPU,
		}

		if err := mgr.Start(context.Background(), cfg); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		return c.JSON(http.StatusOK, map[string]string{"status": "started", "name": req.Name})
	})

	// Get logs
	api.GET("/containers/:id/logs", func(c echo.Context) error {
		id := c.Param("id")
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(id) {
			return c.String(http.StatusBadRequest, "Invalid container ID")
		}
		dir, err := state.ContainerDir(id)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
		logPath := filepath.Join(dir, "logs", "console.log")
		data, err := os.ReadFile(logPath)
		if err != nil {
			return c.String(http.StatusNotFound, "Logs not found or container not started")
		}
		return c.String(http.StatusOK, string(data))
	})

		// Delete container
	api.DELETE("/containers/:id", func(c echo.Context) error {
		id := c.Param("id")
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(id) {
			return c.String(http.StatusBadRequest, "Invalid container ID")
		}

		// 终止进程：不能仅凭持久化的 PID 直接 kill，PID 可能已被复用。
		// 校验进程仍在容器 cgroup 内才终止，并传播 kill 错误。
		st, err := state.LoadState(id)
		if err == nil && st.PID > 0 {
			if proc, err := os.FindProcess(st.PID); err == nil {
				if belongs, _ := procBelongsToContainer(st.PID, id); belongs {
					if killErr := proc.Kill(); killErr != nil && killErr.Error() != "os: process already finished" {
						return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to kill process %d: %v", st.PID, killErr)})
					}
				}
			}
		}

		dir, err := state.ContainerDir(id)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if err := os.RemoveAll(dir); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to remove container dir: %v", err)})
		}

		return c.String(http.StatusOK, "Deleted")
	})

	// Snapshot container
	api.POST("/containers/:id/snapshot", func(c echo.Context) error {
		id := c.Param("id")
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid container ID"})
		}
		dest := filepath.Join("/var/lib/uml-container/containers", id+".tgz")
		if err := snapshot.Export(id, dest); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "success", "file": dest})
	})

	// Restore container
	api.POST("/containers/:id/restore", func(c echo.Context) error {
		id := c.Param("id")
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid container ID"})
		}
		src := filepath.Join("/var/lib/uml-container/containers", id+".tgz")
		if err := snapshot.Import(src, id+"-restored"); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "success", "new_id": id+"-restored"})
	})
	// End of restore container

	// Pull image
	api.POST("/images/pull", func(c echo.Context) error {
		type PullReq struct {
			Image string `json:"image"`
		}
		var req PullReq
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.Image == "" {
			req.Image = "alpine"
		}
		if err := image.Pull(req.Image); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "pulled", "image": req.Image})
	})

	// /exec is the Tool/Policy Gateway endpoint (plan.md §6). The E2B SDK's
	// "run a command" call is routed through the per-task policy gateway so
	// every tool invocation is decided, sanitized, and audited.
	api.POST("/exec", func(c echo.Context) error {
		var req ExecRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		taskID := c.QueryParam("task")
		if taskID == "" {
			taskID = c.Request().Header.Get("X-Task-Id")
		}
		if taskID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "task id required (?task= or X-Task-Id)"})
		}
		gw := gateways.get(taskID)
		if gw == nil {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "no policy gateway registered for task"})
		}
		// Parse "name arg=val arg2=val2 ..." into a ToolRequest.
		treq, err := parseExecCommand(req.Command)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		resp, err := gw.Execute(treq)
		if err != nil {
			// approval-required is a 202, not a hard error
			if errors.Is(err, policyErrApproval()) {
				return c.JSON(http.StatusAccepted, map[string]interface{}{"status": "approval_required"})
			}
			return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, resp)
	})

	// ============================================================
	// Sandbox control plane endpoints (plan.md §3-§12)
	// These expose the new control planes to the WebUI and operators.
	// ============================================================

	// --- Tasks (lifecycle FSM + TaskSpec launch) ---

	// GET /api/tasks — list all tasks with their FSM state.
	api.GET("/tasks", func(c echo.Context) error {
		list, err := state.ListAll()
		if err != nil {
			return c.JSON(http.StatusOK, []interface{}{})
		}
		return c.JSON(http.StatusOK, list)
	})

	// GET /api/tasks/:id — full task state including transition history.
	api.GET("/tasks/:id", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		st, err := state.LoadState(id)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "task not found"})
		}
		return c.JSON(http.StatusOK, st)
	})

	// POST /api/tasks/:id/transition — drive the FSM. Body: {to, actor, reason}.
	api.POST("/tasks/:id/transition", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		var req struct {
			To     string `json:"to"`
			Actor  string `json:"actor"`
			Reason string `json:"reason"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		// Hold the per-task mutex across Load -> Transition -> Save so concurrent
		// transitions on the SAME task serialize instead of clobbering each other.
		mu := taskLock(id)
		mu.Lock()
		defer mu.Unlock()
		st, err := state.LoadState(id)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "task not found"})
		}
		if err := st.Transition(state.Status(req.To), state.Actor(req.Actor), req.Reason); err != nil {
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		if err := state.SaveState(id, st); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, st)
	})

	// POST /api/tasks/load-spec — validate a TaskSpec TOML without launching.
	// Body: {path: "..."} or {content: "<toml>"}. Returns the parsed spec + fingerprint.
	api.POST("/tasks/load-spec", func(c echo.Context) error {
		var req struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		var s *spec.TaskSpec
		var err error
		if req.Path != "" {
			s, err = spec.LoadFile(req.Path)
		} else if req.Content != "" {
			s, err = spec.LoadString(req.Content)
		} else {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "provide path or content"})
		}
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"spec":        s,
			"fingerprint": s.Fingerprint(),
		})
	})

	// --- Audit ledger (plan.md §14) ---

	// GET /api/audit/:id — full ledger for a task (RECONSTRUCT view).
	api.GET("/audit/:id", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		l, err := audit.Open(id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		records, err := l.ReadAll()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, records)
	})

	// GET /api/audit/:id/verify — replay the hash chain; reports broken links.
	api.GET("/audit/:id/verify", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		l, err := audit.Open(id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		n, err := l.Verify()
		resp := map[string]interface{}{"records": n, "valid": err == nil}
		if err != nil {
			resp["error"] = err.Error()
		}
		return c.JSON(http.StatusOK, resp)
	})

	// --- Approval tickets (plan.md §10) ---

	// GET /api/approvals — list pending tickets (optional ?task=id).
	api.GET("/approvals", func(c echo.Context) error {
		m := currentApprovals()
		if c.QueryParam("all") == "1" {
			// include decided ones too: iterate via Pending on empty + decided list
		}
		return c.JSON(http.StatusOK, m.Pending(c.QueryParam("task")))
	})

	// POST /api/approvals — create a ticket.
	api.POST("/approvals", func(c echo.Context) error {
		var t approval.Ticket
		if err := c.Bind(&t); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		id, err := currentApprovals().Create(t)
		if err != nil {
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"id": id})
	})

	// POST /api/approvals/:id/decide — approve/reject. Body: {approved: bool, by: "..."}.
	api.POST("/approvals/:id/decide", func(c echo.Context) error {
		id := c.Param("id")
		var req struct {
			Approved bool   `json:"approved"`
			By       string `json:"by"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		m := currentApprovals()
		if err := m.Decide(id, req.Approved, req.By); err != nil {
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		t, _ := m.Get(id)
		return c.JSON(http.StatusOK, t)
	})

	// --- Policy gateway (plan.md §6) ---

	// GET /api/policy/:task — the compiled tool rules registered for a task.
	api.GET("/policy/:task", func(c echo.Context) error {
		task := c.Param("task")
		gw := globalRegistries.get(task)
		if gw == nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no gateway for task"})
		}
		return c.JSON(http.StatusOK, gw.Rules())
	})

	// --- Pool / Quota (plan.md §12) ---

	// GET /api/pool/stats — ready/claimed/total counts.
	api.GET("/pool/stats", func(c echo.Context) error {
		ready, claimed, total := currentPool().Stats()
		return c.JSON(http.StatusOK, map[string]int{
			"ready": ready, "claimed": claimed, "total": total,
		})
	})

	// POST /api/pool/warm — pre-create sandboxes. Body: {template, n}.
	api.POST("/pool/warm", func(c echo.Context) error {
		var req struct {
			Template pool.Template `json:"template"`
			N        int           `json:"n"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.N <= 0 || req.N > 100 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "n must be 1..100"})
		}
		created := currentPool().Warm(req.Template, req.N)
		return c.JSON(http.StatusOK, map[string]int{"created": created})
	})

	// POST /api/pool/quota — set per-tenant quota. Body: {tenant, quota}.
		api.POST("/pool/quota", func(c echo.Context) error {
		var req struct {
			Tenant string      `json:"tenant"`
			Quota  pool.Quota  `json:"quota"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		currentPool().SetQuota(req.Tenant, req.Quota)
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	// --- Artifact Gate (plan.md §7) ---

	// POST /api/gate/verify — run the Artifact Gate on a submitted bundle.
	// Body: artifact.Bundle JSON. Returns the verdict (pass/fail per step + hash).
	api.POST("/gate/verify", func(c echo.Context) error {
		var b artifact.Bundle
		if err := c.Bind(&b); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		l, err := audit.Open(b.TaskID)
		if err != nil {
			l = nil // degrade to no-ledger; gate still runs
		}
		g := artifact.NewGate(l)
		v := g.Verify(&b)
		return c.JSON(http.StatusOK, v)
	})

	// Serve the embedded Nuxt UI for all other routes
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Root:       ".",
		Filesystem: webui.GetPublicFS(),
		HTML5:      true,
	}))

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("E2B-compatible API & WebUI Server listening on %s\n", addr)
	return e.Start(addr)
}

// procBelongsToContainer reports whether the process with the given pid still
// belongs to the container's cgroup v2 path. We avoid trusting a persisted PID
// blindly because PIDs get recycled; a recycled PID could point at an
// unrelated host process.
//
// It returns (true, nil) only when /proc/<pid>/cgroup references the
// container's cgroup leaf (/<root>/.../<id>). On any parse failure or when the
// process is gone, it returns (false, nil) so callers err on the side of NOT
// killing.
func procBelongsToContainer(pid int, containerID string) (bool, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false, err
	}
	defer f.Close()

	want := "/" + containerID
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2 format: 0::/path/to/cgroup
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		path := fields[2]
		if strings.HasSuffix(path, want) || strings.Contains(path, want+"/") {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// itoa is a small helper kept to avoid pulling strconv elsewhere in this file.
var _ = strconv.Itoa

// gatewayRegistry maps task id -> *policy.Gateway. It is process-local and
// goroutine-safe; agentpvm run registers a gateway per task it boots.
type gatewayRegistry struct {
	mu   sync.RWMutex
	data map[string]*policy.Gateway
}

func newGatewayRegistry() *gatewayRegistry {
	return &gatewayRegistry{data: make(map[string]*policy.Gateway)}
}
func (r *gatewayRegistry) register(taskID string, g *policy.Gateway) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[taskID] = g
}
func (r *gatewayRegistry) get(taskID string) *policy.Gateway {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.data[taskID]
}

// RegisterGateway exposes the registry so the controller (agentpvm) can wire a
// task's policy gateway into the /exec endpoint when the API runs in-process.
var globalRegistries = newGatewayRegistry()

// RegisterPolicyGateway lets agentpvm register a task's policy gateway so
// /api/exec can dispatch to it.
func RegisterPolicyGateway(taskID string, g *policy.Gateway) { globalRegistries.register(taskID, g) }

// parseExecCommand turns a flat command string "name k=v k2=v2" into a
// structured ToolRequest for the policy gateway. Simplest viable contract;
// structured JSON bodies can be added later without breaking this.
// Positional arguments are keyed arg0/arg1/... by a DEDICATED counter so
// earlier key=value params don't shift the positional index.
func parseExecCommand(cmd string) (policy.ToolRequest, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return policy.ToolRequest{}, fmt.Errorf("empty command")
	}
	parts := strings.Fields(cmd)
	req := policy.ToolRequest{Name: parts[0], Args: map[string]interface{}{}}
	positional := 0
	for _, p := range parts[1:] {
		if i := strings.IndexByte(p, '='); i > 0 {
			req.Args[p[:i]] = p[i+1:]
		} else {
			req.Args[fmt.Sprintf("arg%d", positional)] = p
			positional++
		}
	}
	return req, nil
}

// policyErrApproval returns the sentinel approval error so the /exec handler
// can compare via errors.Is without importing policy directly at the call site.
func policyErrApproval() error { return policy.ErrApprovalRequired }

// idRegex is the shared container/task id validator.
var idRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// taskTransitionMu gives per-task mutual exclusion for the /transition
// endpoint (and any other handler that does LoadState -> mutate -> SaveState).
// Without it, two concurrent transitions on the same task each load the same
// stale state and the second SaveState silently clobbers the first's
// transition. Different tasks still proceed in parallel.
var (
	taskTransitionMu    sync.Mutex
	taskTransitionLocks = map[string]*sync.Mutex{}
)

// taskLock returns the mutex guarding transitions for id, creating it on
// first use. The outer mutex is held only briefly to look up/create the
// per-task mutex.
func taskLock(id string) *sync.Mutex {
	taskTransitionMu.Lock()
	defer taskTransitionMu.Unlock()
	mu, ok := taskTransitionLocks[id]
	if !ok {
		mu = &sync.Mutex{}
		taskTransitionLocks[id] = mu
	}
	return mu
}

// Package-level singletons for the control planes exposed via the REST API.
// These are process-local; the controller (agentpvm run) and the API server
// share them when running in the same process. In a multi-process deployment
// they would be backed by a shared store. All reads/writes go through
// planesMu so concurrent Register* calls (e.g. from a live controller and a
// test setup) don't race.
var (
	globalApprovals = approval.NewManager(nil)
	globalPool      = pool.NewManager(16, nil)
	planesMu        sync.RWMutex
)

// RegisterApprovalManager lets the controller inject its own approval manager
// (e.g. one wired to a real audit ledger) to replace the default.
func RegisterApprovalManager(m *approval.Manager) {
	planesMu.Lock()
	globalApprovals = m
	planesMu.Unlock()
}

// RegisterPoolManager lets the controller inject its own pool manager.
func RegisterPoolManager(m *pool.Manager) {
	planesMu.Lock()
	globalPool = m
	planesMu.Unlock()
}

// currentApprovals returns the registered approval manager under planesMu.
func currentApprovals() *approval.Manager {
	planesMu.RLock()
	defer planesMu.RUnlock()
	return globalApprovals
}

// currentPool returns the registered pool manager under planesMu.
func currentPool() *pool.Manager {
	planesMu.RLock()
	defer planesMu.RUnlock()
	return globalPool
}
