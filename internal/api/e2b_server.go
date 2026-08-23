package api

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"uml-container/internal/approval"
	"uml-container/internal/artifact"
	"uml-container/internal/audit"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/cow"
	"uml-container/internal/image"
	"uml-container/internal/lifecycle"
	"uml-container/internal/policy"
	"uml-container/internal/pool"
	"uml-container/internal/snapshot"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/template"
	"uml-container/internal/volume"
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

// NewE2BServer configures and returns an Echo instance with all E2B API and WebUI routes.
func NewE2BServer() (*echo.Echo, error) {
	e := echo.New()

	// Shared lifecycle manager: injected into container.Managers created by
	// this server (so StartTask arms autopause timers) and reused by the
	// pause/resume and activity endpoints below instead of separate instances.
	cgMgr := cgroup.NewManager()
	autoMgr := lifecycle.New(cgMgr)
	// Autopause timers live in process memory: tasks persisted as Running
	// by a previous server process have no timers after a restart. Re-arm
	// them from the persisted IdleTimeout so an idle task still suspends
	// without waiting for the next lifecycleActivity request. The idle
	// window restarts at its full duration (persisting the exact deadline
	// across restarts is not tracked).
	rearmAllAutopause(autoMgr)

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000", "http://127.0.0.1:3000"},
	}))

	// API Group
	api := e.Group("/api")
	// API_SECRET is REQUIRED: there is no hardcoded fallback. A missing
	// secret is a configuration error (we never want to silently
	// authenticate everyone who guesses "secret" — the CLI side already
	// refuses the symmetric default, see cmd/agentpvm approvalCmd).
	apiSecret := os.Getenv("API_SECRET")
	if apiSecret == "" {
		return nil, errors.New("API_SECRET environment variable is required (refusing to start the API with no authentication)")
	}
	apiSecretBytes := []byte(apiSecret)
	api.Use(middleware.KeyAuth(func(key string, c echo.Context) (bool, error) {
		// Constant-time compare: the secret guards every control-plane
		// endpoint (approvals, policy, quota), so timing side channels are
		// worth closing even on loopback.
		if subtle.ConstantTimeCompare([]byte(key), apiSecretBytes) == 1 {
			c.Set("actor", "api-user")
			return true, nil
		}
		return false, nil
	}))

	// E2B SDK-compatible surface (see e2b_compat.go): root-level
	// /sandboxes routes so official E2B SDKs can drive PVM.
	registerE2BCompat(e, apiSecretBytes, autoMgr)

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
			Name      string `json:"name"`
			Rootfs    string `json:"rootfs"`
			Mem       string `json:"mem"`
			CPU       int    `json:"cpu"`
			Ephemeral bool   `json:"ephemeral"`
		}
		var req StartReq
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.Name == "" {
			req.Name = "web-container"
		}

		if !idRegex.MatchString(req.Name) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid container ID format"})
		}
		if req.CPU < 0 || req.CPU > 1024 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "CPU limit must be between 0 and 1024"})
		}
		// Rootfs is interpolated into the UML kernel command line (ubd0=<path>).
		// The kernel re-splits argv on whitespace, so an unvalidated value can
		// inject arbitrary kernel parameters (hostfs_volume=/:/mnt, init=...)
		// or point the sandbox at another task's disk. Constrain it to an
		// absolute path inside the image root, with no traversal/whitespace,
		// and keep the RESOLVED path so later stages (buildLegacyArgs /
		// validateRootfs) use the trusted path that was actually checked.
		resolvedRootfs, err := validateAPIRootfs(req.Rootfs)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		req.Rootfs = resolvedRootfs

		mgr := container.NewManager(nil)
		mgr.Autopause = autoMgr
		mem := req.Mem
		if mem == "" {
			mem = "512M"
		}
		memBytes, err := config.ParseMemory(mem)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		cfg := &config.ContainerConfig{
			ID:     req.Name,
			Name:   req.Name,
			Rootfs: req.Rootfs,
			Kernel: "./bin/linux",
			Init:   "/init.sh",
			// Canonical numeric form ONLY: ParseMemory (Sscanf %d%s) ignores
			// trailing input, so "512M init=/bin/sh" would pass parsing and the
			// raw string would land on the kernel command line. Never forward
			// the caller's original spelling.
			Memory:      strconv.FormatInt(memBytes, 10),
			MemoryBytes: memBytes,
			CPU:         req.CPU,
			// Ephemeral mounts the rootfs read-only: nothing the guest writes
			// persists (see ContainerConfig.Ephemeral). Writable scratch is
			// the guest init's tmpfs — /init.sh consumers mount it themselves.
			Ephemeral: req.Ephemeral,
		}

		if err := mgr.Start(context.Background(), cfg); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		return c.JSON(http.StatusOK, map[string]string{"status": "started", "name": req.Name})
	})

	// Get logs
	api.GET("/containers/:id/logs", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
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
		if !idRegex.MatchString(id) {
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
		// A clone's overlay backing reaches INTO this container's directory
		// (absolute backing path recorded in the qcow2 header). Refuse to
		// delete while live clones branch from it; PrepareDelete also drops
		// this container's own marker from its parent when it IS a clone.
		if err := snapshot.PrepareDelete(id); err != nil {
			if errors.Is(err, snapshot.ErrHasClones) {
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if err := os.RemoveAll(dir); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to remove container dir: %v", err)})
		}

		return c.String(http.StatusOK, "Deleted")
	})

	// Snapshot container
	api.POST("/containers/:id/snapshot", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
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
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid container ID"})
		}
		src := filepath.Join("/var/lib/uml-container/containers", id+".tgz")
		if err := snapshot.Import(src, id+"-restored"); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "success", "new_id": id + "-restored"})
	})
	// End of restore container

	// Clone container
	api.POST("/containers/:id/clone", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid container ID"})
		}
		var req struct {
			NewID string `json:"new_id"`
		}
		if err := c.Bind(&req); err != nil || req.NewID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "new_id is required"})
		}
		if !idRegex.MatchString(req.NewID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid new_id format"})
		}
		if err := snapshot.Clone(id, req.NewID); err != nil {
			if strings.Contains(err.Error(), "already exists") {
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			}
			if strings.Contains(err.Error(), "not found") {
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "cloned", "id": req.NewID, "source_id": id})
	})

	// Rollback container
	api.POST("/containers/:id/rollback", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid container ID"})
		}
		var req struct {
			SnapshotID string `json:"snapshot_id"`
			Force      bool   `json:"force"`
		}
		if err := c.Bind(&req); err != nil || req.SnapshotID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "snapshot_id is required"})
		}
		if !idRegex.MatchString(req.SnapshotID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid snapshot_id format"})
		}
		release := taskLock(id)
		defer release()
		if err := snapshot.RollbackWithForce(id, req.SnapshotID, req.Force); err != nil {
			if errors.Is(err, snapshot.ErrSpecMismatch) {
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			}
			if strings.Contains(err.Error(), "not found") {
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "rolled_back", "id": id, "snapshot_id": req.SnapshotID})
	})

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
		// API activity counts for lifecycle policy: bump the idle timer of a
		// Running task, or auto-resume a Suspended one when its config allows.
		// st is nil here: /exec does not need the state itself, so the helper
		// loads it once internally.
		lifecycleActivity(taskID, autoMgr, nil)
		// Parse "name arg=val arg2=val2 ..." into a ToolRequest.
		treq, err := parseExecCommand(req.Command)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		gw := gateways.get(taskID)
		if gw == nil {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "no policy gateway registered for task"})
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
		release := taskLock(id)
		defer release()
		st, err := state.LoadState(id)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "task not found"})
		}
		// API activity bumps a RUNNING task's idle deadline — reusing the
		// state already loaded above so the request pays one synchronous disk
		// read instead of two. Unlike /exec's lifecycleActivity this NEVER
		// auto-resumes: an explicit transition on a Suspended task must be
		// validated by the FSM below (and rejected for invalid edges), not
		// silently turned into a resume.
		bumpIdleTimer(st, autoMgr)
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
			// Arbitrary host paths are an information disclosure (any file the
			// daemon can read gets parsed and echoed back, secrets included).
			// Constrain path loads to the operator-designated spec root.
			root := os.Getenv("PVM_SPEC_ROOT")
			if root == "" {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "path loading disabled: set PVM_SPEC_ROOT or send content"})
			}
			// Plain '=' assignments into the OUTER err — a ':=' here would
			// shadow it and let a LoadFile failure slip past the check below,
			// dereferencing a nil spec in the response.
			var absRoot, abs string
			absRoot, err = filepath.Abs(root)
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			abs, err = filepath.Abs(req.Path)
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			// Resolve symlinks BEFORE the containment check (same policy as
			// validateHostPath): a lexical path inside PVM_SPEC_ROOT that
			// symlinks outside must be rejected, and a root that itself contains
			// symlinks must contain its RESOLVED children.
			absRootR, rerr := filepath.EvalSymlinks(absRoot)
			if rerr != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot resolve PVM_SPEC_ROOT: " + rerr.Error()})
			}
			absR, rerr := filepath.EvalSymlinks(abs)
			if rerr != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot resolve spec path: " + rerr.Error()})
			}
			if absR != absRootR && !strings.HasPrefix(absR, absRootR+string(filepath.Separator)) {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "path must stay inside PVM_SPEC_ROOT"})
			}
			s, err = spec.LoadFile(absR)
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

	// --- Event Snapshots & Task Clone / Rollback ---

	// POST /api/tasks/:id/snapshots — create event-level snapshot
	api.POST("/tasks/:id/snapshots", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		var req struct {
			EventID   string            `json:"event_id"`
			AuditHash string            `json:"audit_hash"`
			Metadata  map[string]string `json:"metadata"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "bad request: " + err.Error()})
		}
		snap, err := snapshot.CreateEventSnapshot(id, req.EventID, req.AuditHash, req.Metadata)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, snap)
	})

	// GET /api/tasks/:id/snapshots — list event snapshots for a task
	api.GET("/tasks/:id/snapshots", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		list, err := snapshot.ListEventSnapshots(id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, list)
	})

	// GET /api/tasks/:id/snapshots/:snapId — get event snapshot detail
	api.GET("/tasks/:id/snapshots/:snapId", func(c echo.Context) error {
		id := c.Param("id")
		snapId := c.Param("snapId")
		if !idRegex.MatchString(id) || !idRegex.MatchString(snapId) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id format"})
		}
		snap, err := snapshot.GetEventSnapshot(id, snapId)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, snap)
	})

	// DELETE /api/tasks/:id/snapshots/:snapId — delete event snapshot
	api.DELETE("/tasks/:id/snapshots/:snapId", func(c echo.Context) error {
		id := c.Param("id")
		snapId := c.Param("snapId")
		if !idRegex.MatchString(id) || !idRegex.MatchString(snapId) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id format"})
		}
		if err := snapshot.DeleteEventSnapshot(id, snapId); err != nil {
			if errors.Is(err, snapshot.ErrSnapshotInUse) {
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			}
			if strings.Contains(err.Error(), "not found") {
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.String(http.StatusOK, "Deleted")
	})

	// POST /api/tasks/:id/clone — instant clone a task
	api.POST("/tasks/:id/clone", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid source task id"})
		}
		var req struct {
			NewID string `json:"new_id"`
		}
		if err := c.Bind(&req); err != nil || req.NewID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "new_id is required"})
		}
		if !idRegex.MatchString(req.NewID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid new_id format"})
		}
		if err := snapshot.Clone(id, req.NewID); err != nil {
			if strings.Contains(err.Error(), "already exists") {
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			}
			if strings.Contains(err.Error(), "not found") {
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if l, lerr := audit.Open(req.NewID); lerr == nil {
			_ = l.Append(audit.Record{
				Phase:    audit.PhaseExec,
				Subject:  "system",
				Action:   "clone",
				Params:   map[string]string{"source_id": id},
				Decision: audit.DecisionAllow,
				Reason:   "instant clone from " + id,
			})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "cloned", "id": req.NewID, "source_id": id})
	})

	// POST /api/tasks/:id/rollback — historical rollback
	api.POST("/tasks/:id/rollback", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		var req struct {
			SnapshotID string `json:"snapshot_id"`
			Force      bool   `json:"force"`
		}
		if err := c.Bind(&req); err != nil || req.SnapshotID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "snapshot_id is required"})
		}
		if !idRegex.MatchString(req.SnapshotID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid snapshot_id format"})
		}
		release := taskLock(id)
		defer release()
		if err := snapshot.RollbackWithForce(id, req.SnapshotID, req.Force); err != nil {
			if errors.Is(err, snapshot.ErrSpecMismatch) {
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			}
			if strings.Contains(err.Error(), "not found") {
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if l, lerr := audit.Open(id); lerr == nil {
			_ = l.Append(audit.Record{
				Phase:    audit.PhaseExec,
				Subject:  "human",
				Action:   "rollback",
				Params:   map[string]string{"snapshot_id": req.SnapshotID},
				Decision: audit.DecisionAllow,
				Reason:   "historical rollback to " + req.SnapshotID,
			})
		}
		st, err := state.LoadState(id)
		if err != nil {
			// The rollback itself succeeded, but a state that cannot be
			// reloaded afterwards is an anomaly that must be surfaced, not
			// hidden as a null "state" field inside a success response.
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("rollback succeeded but reloading state failed: %v", err)})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{"status": "rolled_back", "id": id, "snapshot_id": req.SnapshotID, "state": st})
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
			// Bad caller input (deadline outside the sane window) is a 400;
			// everything else keeps the existing 409 (duplicate pending ticket).
			if errors.Is(err, approval.ErrInvalidDeadline) {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"id": id})
	})

	// POST /api/approvals/:id/decide — approve/reject. Body: {approved: bool}.
	api.POST("/approvals/:id/decide", func(c echo.Context) error {
		id := c.Param("id")
		var req struct {
			Approved bool   `json:"approved"`
			By       string `json:"by"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		actor, _ := c.Get("actor").(string)
		if actor == "" {
			actor = "operator"
		}
		m := currentApprovals()
		if err := m.Decide(id, req.Approved, actor); err != nil {
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

	// POST /api/policy/:task — register or update compiled tool rules for a task.
	api.POST("/policy/:task", func(c echo.Context) error {
		task := c.Param("task")
		if !idRegex.MatchString(task) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		var req struct {
			Rules []policy.Rule `json:"rules"`
			Force bool          `json:"force"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		// Keep decisions auditable: open the task's ledger instead of nil.
		// Degrade to nil (gate still runs) only if the ledger cannot open.
		l, lerr := audit.Open(task)
		if lerr != nil {
			log.Printf("api: policy gateway for %s runs WITHOUT audit ledger: %v", task, lerr)
			l = nil
		}
		gw := policy.NewGateway(req.Rules, l)
		// Replacing a task's gateway silently de-registers its audit trail
		// (a nil ledger) and swaps its tool policy. Require an explicit force
		// to override an existing registration. The check+write happens inside
		// the registry's registerIfAbsent under ONE lock: a separate get()
		// check here would let two concurrent registrations both pass and
		// silently clobber each other.
		if req.Force {
			RegisterPolicyGateway(task, gw)
		} else if !gateways.registerIfAbsent(task, gw) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "policy gateway already registered for task; send force=true to override"})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{"status": "registered", "rules": gw.Rules()})
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
			Tenant string     `json:"tenant"`
			Quota  pool.Quota `json:"quota"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.Tenant == "" || !idRegex.MatchString(req.Tenant) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid tenant id"})
		}
		if req.Quota.MaxConcurrent < 0 || req.Quota.MaxCPU < 0 || req.Quota.MaxMemoryMB < 0 || req.Quota.MaxTasksPerHour < 0 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "quota limits cannot be negative"})
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
		// TaskID reaches audit.Open (directory construction): the same
		// idRegex the /api/audit/:id endpoints enforce. Without it a
		// "../../..." id writes ledgers outside the audit root.
		if b.TaskID != "" && !idRegex.MatchString(b.TaskID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		l, err := audit.Open(b.TaskID)
		if err != nil {
			l = nil // degrade to no-ledger; gate still runs
		}
		g := artifact.NewGate(l)
		v := g.Verify(&b)
		return c.JSON(http.StatusOK, v)
	})

	// --- Volumes (Cube parity: POST/GET/DELETE /volumes) ---
	// One root for metadata AND blocks: records colocate with the cow
	// engine's qcow2 files (PVM_VOLUME_ROOT, else the engine's PVM_COW_ROOT
	// fallback via cow.ResolveRoot) so the registry and the block images it
	// describes can never drift into different directories. volume.NewStore's
	// own fallback (DefaultVolumeBaseDir) stays reserved for the plugin-mount
	// manager — a separate concern (hostPath mounts, not block storage).
	volStore := volume.NewStore(cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT")))
	// Volume API responses intentionally exclude Token and PrivateData: those
	// are credentials for mount plugins (internal paths read them from the
	// store), never for API clients.
	type volumeResponse struct {
		VolumeID  string    `json:"volume_id"`
		Name      string    `json:"name"`
		Driver    string    `json:"driver"`
		RefCount  int       `json:"refcount"`
		CreatedAt time.Time `json:"created_at"`
	}
	toVolumeResponse := func(r volume.VolumeRecord) volumeResponse {
		return volumeResponse{
			VolumeID:  r.VolumeID,
			Name:      r.Name,
			Driver:    r.Driver,
			RefCount:  r.RefCount,
			CreatedAt: r.CreatedAt,
		}
	}
	api.POST("/volumes", func(c echo.Context) error {
		var req struct {
			Name        string `json:"name"`
			Driver      string `json:"driver"`
			Token       string `json:"token"`
			PrivateData string `json:"private_data"`
			Size        int64  `json:"size"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.Name == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "name required"})
		}
		// The builtin driver's volumes are cow block images: provision the
		// qcow2 up front (size defaults to 64 MiB) so snapshot/clone/rollback
		// operate on a real image instead of a metadata-only record. Other
		// drivers (nfs, s3, plugin binaries) stay metadata-only — their
		// storage is owned externally.
		blockCreated := false
		if req.Driver == "builtin" {
			if req.Size < 0 || req.Size > 1<<40 {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "size must be between 0 and 1 TiB"})
			}
			size := req.Size
			if size == 0 {
				size = 64 << 20
			}
			if _, err := cow.NewEngine(cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT"))).CreateVolume(req.Name, uint64(size)); err != nil {
				msg := err.Error()
				switch {
				case errors.Is(err, cow.ErrExists):
					return c.JSON(http.StatusConflict, map[string]string{"error": msg})
				case errors.Is(err, cow.ErrInvalid):
					return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
				default:
					return c.JSON(http.StatusInternalServerError, map[string]string{"error": msg})
				}
			}
			blockCreated = true
		}
		rec := volume.VolumeRecord{VolumeID: req.Name, Name: req.Name, Driver: req.Driver, Token: req.Token, PrivateData: req.PrivateData}
		if err := volStore.Create(rec); err != nil {
			if blockCreated {
				// Roll the freshly created block back out: the registry is the
				// source of truth, and a block without a record would 409-block
				// every future create of the same name.
				_ = cow.NewEngine(cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT"))).DeleteVolume(req.Name)
			}
			switch {
			case errors.Is(err, volume.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, volume.ErrExists):
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		got, err := volStore.Get(req.Name)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusCreated, toVolumeResponse(*got))
	})
	api.GET("/volumes", func(c echo.Context) error {
		list, err := volStore.List()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if list == nil {
			list = []volume.VolumeRecord{}
		}
		out := make([]volumeResponse, 0, len(list))
		for _, r := range list {
			out = append(out, toVolumeResponse(r))
		}
		return c.JSON(http.StatusOK, out)
	})
	api.GET("/volumes/:id", func(c echo.Context) error {
		id := c.Param("id")
		rec, err := volStore.Get(id)
		if err != nil {
			switch {
			case errors.Is(err, volume.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, volume.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		return c.JSON(http.StatusOK, toVolumeResponse(*rec))
	})
	api.DELETE("/volumes/:id", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid volume id"})
		}
		// Mounted volumes must be rejected BEFORE any block cleanup: the
		// refcount lives in the record, so consult it first instead of
		// deleting the image out from under a live mount.
		rec, err := volStore.Get(id)
		if err != nil {
			switch {
			case errors.Is(err, volume.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, volume.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		if rec.RefCount > 0 {
			return c.JSON(http.StatusConflict, map[string]string{"error": fmt.Sprintf("volume %q is mounted (refcount=%d)", id, rec.RefCount)})
		}
		// Remove the block image (if this driver has one) through the
		// engine's reference guard: dependents (clones, snapshots) veto the
		// delete instead of being silently orphaned on a broken chain.
		volRoot := cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT"))
		if _, serr := os.Stat(filepath.Join(volRoot, id+".qcow2")); serr == nil {
			if derr := cow.NewEngine(volRoot).DeleteVolume(id); derr != nil {
				switch {
				case errors.Is(derr, cow.ErrReferenced), errors.Is(derr, cow.ErrRefScan):
					return c.JSON(http.StatusConflict, map[string]string{"error": derr.Error()})
				case errors.Is(derr, cow.ErrNotFound):
					// Raced away underneath us; metadata still needs cleaning.
				default:
					return c.JSON(http.StatusInternalServerError, map[string]string{"error": derr.Error()})
				}
			}
		}
		if err := volStore.Delete(id); err != nil {
			switch {
			case errors.Is(err, volume.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, volume.ErrStillMounted):
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			case errors.Is(err, volume.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		return c.NoContent(http.StatusNoContent)
	})

	// POST /api/volumes/:id/clone — clone volume via CoW
	api.POST("/volumes/:id/clone", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid volume id"})
		}
		var req struct {
			NewID string `json:"new_id"`
		}
		if err := c.Bind(&req); err != nil || req.NewID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "new_id is required"})
		}
		if !idRegex.MatchString(req.NewID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid new_id format"})
		}
		rec, err := volStore.Get(id)
		if err != nil {
			if errors.Is(err, volume.ErrNotFound) {
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		newRec := volume.VolumeRecord{
			VolumeID:    req.NewID,
			Name:        req.NewID,
			Driver:      rec.Driver,
			Token:       rec.Token,
			PrivateData: rec.PrivateData,
			CreatedAt:   time.Now().UTC(),
		}
		if err := volStore.Create(newRec); err != nil {
			if errors.Is(err, volume.ErrExists) {
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		// Resolve the root ONCE and derive both the engine and the vol/snap
		// paths from it: joining the raw environment variable diverges from
		// NewEngine's fallback when PVM_VOLUME_ROOT is empty (Join("", ...) is
		// CWD-relative), so the stat checks below would observe a different
		// directory than the engine clones from.
		volRoot := cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT"))
		engine := cow.NewEngine(volRoot)
		volFile := filepath.Join(volRoot, id+".qcow2")
		snapFile := filepath.Join(volRoot, "snap-"+id+".qcow2")
		// CloneVolume resolves the source itself and falls back to the
		// snap-<id>.qcow2 image when <id>.qcow2 is absent, so BOTH cases
		// clone by volume id; the stats only decide whether any image exists.
		if _, verr := os.Stat(volFile); verr != nil {
			if _, serr := os.Stat(snapFile); serr != nil {
				// No block image: this is a metadata-only volume (non-builtin
				// driver) or the image was lost. Cloning either is meaningless —
				// fail honestly instead of returning a fake "cloned" with an
				// empty path.
				_ = volStore.Delete(req.NewID)
				return c.JSON(http.StatusNotFound, map[string]string{"error": fmt.Sprintf("volume %q has no block image to clone", id)})
			}
		}
		path, err := engine.CloneVolume(id, req.NewID)
		if err != nil {
			_ = volStore.Delete(req.NewID)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to clone volume: " + err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "cloned", "volume_id": req.NewID, "path": path})
	})

	// POST /api/volumes/:id/rollback — rollback volume to snapshot
	api.POST("/volumes/:id/rollback", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid volume id"})
		}
		var req struct {
			Snapshot string `json:"snapshot"`
		}
		if err := c.Bind(&req); err != nil || req.Snapshot == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "snapshot is required"})
		}
		if !idRegex.MatchString(req.Snapshot) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid snapshot format"})
		}
		engine := cow.NewEngine(cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT")))
		if err := engine.RollbackVolume(id, req.Snapshot); err != nil {
			msg := err.Error()
			switch {
			case errors.Is(err, cow.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": msg})
			case errors.Is(err, cow.ErrBackedBy), errors.Is(err, cow.ErrReferenced), errors.Is(err, cow.ErrRefScan):
				return c.JSON(http.StatusConflict, map[string]string{"error": msg})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": msg})
			}
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "rolled_back", "volume": id, "snapshot": req.Snapshot})
	})

	// POST /api/volumes/:id/snapshots — create a cow snapshot of a volume.
	// Snapshot names are engine-global (snap-<name>.qcow2): :id selects the
	// volume to branch from; an empty name auto-generates one.
	api.POST("/volumes/:id/snapshots", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid volume id"})
		}
		var req struct {
			Snapshot string `json:"snapshot"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		name := req.Snapshot
		if name == "" {
			name = fmt.Sprintf("auto-%d", time.Now().UnixNano())
		}
		if !idRegex.MatchString(name) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid snapshot name"})
		}
		path, err := cow.NewEngine(cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT"))).CreateSnapshot(id, name)
		if err != nil {
			msg := err.Error()
			switch {
			case errors.Is(err, cow.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": msg})
			case errors.Is(err, cow.ErrExists):
				return c.JSON(http.StatusConflict, map[string]string{"error": msg})
			case errors.Is(err, cow.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": msg})
			}
		}
		return c.JSON(http.StatusCreated, map[string]string{"status": "created", "volume": id, "snapshot": name, "path": path})
	})

	// GET /api/volumes/:id/snapshots — list cow snapshots originating from
	// the volume (origin resolution walks the backing chain; snapshots whose
	// chain no longer resolves report an empty origin and are not listed).
	api.GET("/volumes/:id/snapshots", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid volume id"})
		}
		snaps, err := cow.NewEngine(cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT"))).ListSnapshots(id)
		if err != nil {
			if errors.Is(err, cow.ErrInvalid) {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if snaps == nil {
			snaps = []cow.Snapshot{}
		}
		return c.JSON(http.StatusOK, snaps)
	})

	// DELETE /api/volumes/:id/snapshots/:snap — delete a cow snapshot. The
	// engine keys snapshots by GLOBAL name, so :snap addresses the image
	// directly; the engine's reference guard rejects snapshots that live
	// volumes still branch from.
	api.DELETE("/volumes/:id/snapshots/:snap", func(c echo.Context) error {
		if !idRegex.MatchString(c.Param("id")) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid volume id"})
		}
		snap := c.Param("snap")
		if !idRegex.MatchString(snap) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid snapshot name"})
		}
		if err := cow.NewEngine(cow.ResolveRoot(os.Getenv("PVM_VOLUME_ROOT"))).DeleteSnapshot(snap); err != nil {
			msg := err.Error()
			switch {
			case errors.Is(err, cow.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": msg})
			case errors.Is(err, cow.ErrReferenced), errors.Is(err, cow.ErrRefScan):
				return c.JSON(http.StatusConflict, map[string]string{"error": msg})
			case errors.Is(err, cow.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": msg})
			}
		}
		return c.NoContent(http.StatusNoContent)
	})

	// --- Templates (Cube parity: /templates) ---
	tmplStore := template.NewStore("")
	api.POST("/templates", func(c echo.Context) error {
		var req struct {
			ImageRef string `json:"image_ref"`
			Alias    string `json:"alias"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.ImageRef == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "image_ref required"})
		}
		// Creation starts a template's lifecycle in PENDING: a record becomes
		// READY (and may claim an alias — see Store.SetAlias/Create) only after
		// its image build completes, so a freshly registered template must not
		// be handed to sandbox launches yet.
		rec := template.Record{TemplateID: template.GenerateTemplateID(), Alias: req.Alias, ImageRef: req.ImageRef, Status: "PENDING", Kind: "template"}
		if err := tmplStore.Create(rec); err != nil {
			switch {
			case errors.Is(err, template.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, template.ErrConflict):
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		got, err := tmplStore.Get(rec.TemplateID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusCreated, got)
	})
	api.GET("/templates", func(c echo.Context) error {
		list, err := tmplStore.List()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if list == nil {
			list = []template.Record{}
		}
		return c.JSON(http.StatusOK, list)
	})
	api.GET("/templates/:id", func(c echo.Context) error {
		id := c.Param("id")
		resolved, err := tmplStore.ResolveIdentifier(id)
		if err != nil {
			switch {
			case errors.Is(err, template.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, template.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		rec, err := tmplStore.Get(resolved)
		if err != nil {
			switch {
			case errors.Is(err, template.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, template.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		return c.JSON(http.StatusOK, rec)
	})
	api.POST("/templates/:id/alias", func(c echo.Context) error {
		id := c.Param("id")
		var req struct {
			Alias string `json:"alias"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		// Resolve the path param first so BOTH raw ids and aliases work here
		// (mirrors GET /templates/:id); SetAlias/Delete then operate on the
		// canonical template id.
		resolved, err := tmplStore.ResolveIdentifier(id)
		if err != nil {
			switch {
			case errors.Is(err, template.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, template.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		if err := tmplStore.SetAlias(resolved, req.Alias); err != nil {
			switch {
			case errors.Is(err, template.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, template.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			case errors.Is(err, template.ErrConflict):
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		rec, err := tmplStore.Get(resolved)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, rec)
	})
	api.DELETE("/templates/:id", func(c echo.Context) error {
		id := c.Param("id")
		// Resolve aliases to template ids first (mirrors GET /templates/:id).
		resolved, err := tmplStore.ResolveIdentifier(id)
		if err != nil {
			switch {
			case errors.Is(err, template.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, template.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		if err := tmplStore.Delete(resolved); err != nil {
			switch {
			case errors.Is(err, template.ErrInvalid):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, template.ErrNotFound):
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			default:
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
		}
		return c.NoContent(http.StatusNoContent)
	})

	// --- AutoPause (Cube parity: POST /tasks/:id/pause|resume) ---
	api.POST("/tasks/:id/pause", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		// Hold the per-task mutex across Load -> Freeze -> Transition -> Save
		// so concurrent transitions on the SAME task serialize (cf. /transition)
		// and a racing resume cannot clobber the persisted SUSPENDED state.
		release := taskLock(id)
		defer release()
		st, err := state.LoadState(id)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "task not found"})
		}
		if st.Status != state.StatusRunning {
			return c.JSON(http.StatusConflict, map[string]string{"error": fmt.Sprintf("task not running (status=%s)", st.Status)})
		}
		if err := cgMgr.Freeze(id); err != nil {
			// A missing cgroup means the runtime is gone (the task exited); do
			// not persist SUSPENDED for a task that cannot actually be frozen.
			if os.IsNotExist(err) {
				return c.JSON(http.StatusConflict, map[string]string{"error": "task runtime missing (cgroup not found); task may have exited"})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		autoMgr.Disarm(id)
		// reArmAfterFailedPause restores the idle timer after a rollback: the
		// task is back to Running, so autopause must keep watching it.
		reArm := func() {
			if d, derr := time.ParseDuration(st.IdleTimeout); derr == nil && d > 0 {
				autoMgr.Arm(id, d)
			}
		}
		if err := st.Transition(state.StatusSuspended, state.ActorHuman, "manual pause"); err != nil {
			// Roll back the freeze so runtime and persisted state stay in sync
			// (disk still says Running).
			_ = cgMgr.Thaw(id)
			reArm()
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		if err := state.SaveState(id, st); err != nil {
			// Same rollback: the transition was not persisted.
			_ = cgMgr.Thaw(id)
			reArm()
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.NoContent(http.StatusNoContent)
	})
	api.POST("/tasks/:id/resume", func(c echo.Context) error {
		id := c.Param("id")
		if !idRegex.MatchString(id) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		// Same per-task lock as pause: Load -> Thaw -> Transition -> Save must
		// serialize against concurrent pause/transition requests.
		release := taskLock(id)
		defer release()
		if _, err := state.LoadState(id); err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "task not found"})
		}
		// An explicit operator resume is NOT gated on the task's auto_resume
		// config: that flag only governs the automatic resume path in
		// lifecycleActivity (API activity). A request to this endpoint means
		// an operator decided the task must run again.
		if err := autoMgr.Resume(id); err != nil {
			if errors.Is(err, state.ErrInvalidTransition) || errors.Is(err, state.ErrTerminal) {
				return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		st, err := state.LoadState(id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, st)
	})

	// Serve the embedded Nuxt UI for all other routes
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Root:       ".",
		Filesystem: webui.GetPublicFS(),
		HTML5:      true,
	}))

	return e, nil
}

// StartE2BServer starts a REST API compatible with E2B SDK and serves the WebUI on the given port.
func StartE2BServer(port int) error {
	e, err := NewE2BServer()
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("E2B-compatible API & WebUI Server listening on %s\n", addr)
	return e.Start(addr)
}

// rearmAllAutopause restores autopause timers for every persisted RUNNING
// task with a valid idle_timeout, mirroring what StartTask does for fresh
// tasks. Best effort: unparseable/below-zero timeouts are skipped.
func rearmAllAutopause(autoMgr *lifecycle.Manager) {
	sts, err := state.ListAll()
	if err != nil {
		// No state dir (fresh install) or unreadable state: nothing to arm.
		return
	}
	for _, st := range sts {
		if st.Status != state.StatusRunning || st.IdleTimeout == "" {
			continue
		}
		if d, derr := time.ParseDuration(st.IdleTimeout); derr == nil && d > 0 {
			autoMgr.Arm(st.ID, d)
		}
	}
}

// bumpIdleTimer applies the activity half of the lifecycle policy: a
// Running task's idle timer is bumped (Reset) when an idle_timeout is
// configured. It takes state the caller has already loaded (e.g. /transition)
// so a request pays one synchronous disk read, not two.
func bumpIdleTimer(st *state.ContainerState, autoMgr *lifecycle.Manager) {
	if st.Status != state.StatusRunning || st.IdleTimeout == "" {
		return
	}
	if d, derr := time.ParseDuration(st.IdleTimeout); derr == nil && d > 0 {
		autoMgr.Reset(st.ID, d)
	}
}

// lifecycleActivity applies the task's lifecycle policy on API activity:
// a Suspended task with AutoResume=true is resumed, and a Running task's
// idle timer is bumped (Reset) when an idle_timeout is configured. Callers
// that already loaded the task's state pass it in st (avoiding a second
// synchronous disk read); nil makes this load it. Best effort: failures
// never fail the calling endpoint.
func lifecycleActivity(taskID string, autoMgr *lifecycle.Manager, st *state.ContainerState) {
	if st == nil {
		loaded, err := state.LoadState(taskID)
		if err != nil {
			return
		}
		st = loaded
	}
	switch st.Status {
	case state.StatusSuspended:
		if st.AutoResume {
			_ = autoMgr.Resume(taskID)
		}
	case state.StatusRunning:
		bumpIdleTimer(st, autoMgr)
	}
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
func (r *gatewayRegistry) unregister(taskID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.data, taskID)
}
func (r *gatewayRegistry) get(taskID string) *policy.Gateway {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.data[taskID]
}

// registerIfAbsent installs g for taskID only when no gateway is registered
// for it yet, checking AND writing under one lock so two concurrent callers
// cannot both observe "absent" and silently clobber each other's
// registration. Returns false when a gateway already exists (no write done).
func (r *gatewayRegistry) registerIfAbsent(taskID string, g *policy.Gateway) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.data[taskID]; ok {
		return false
	}
	r.data[taskID] = g
	return true
}

// RegisterGateway exposes the registry so the controller (agentpvm) can wire a
// task's policy gateway into the /exec endpoint when the API runs in-process.
var globalRegistries = newGatewayRegistry()

// RegisterPolicyGateway lets agentpvm register a task's policy gateway so
// /api/exec can dispatch to it.
func RegisterPolicyGateway(taskID string, g *policy.Gateway) { globalRegistries.register(taskID, g) }

// UnregisterPolicyGateway removes a task's gateway from the process-local
// registry. Tests use it via t.Cleanup so a registered task does not leak
// across test runs (the registry is a package-level singleton).
func UnregisterPolicyGateway(taskID string) { globalRegistries.unregister(taskID) }

func splitCommandArgs(cmd string) ([]string, error) {
	var args []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	for i := 0; i < len(cmd); i++ {
		b := cmd[i]
		if escaped {
			current.WriteByte(b)
			escaped = false
			continue
		}
		if b == '\\' && !inSingleQuote {
			escaped = true
			continue
		}
		if b == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if b == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}
		if (b == ' ' || b == '\t' || b == '\n') && !inSingleQuote && !inDoubleQuote {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteByte(b)
	}
	if inSingleQuote || inDoubleQuote {
		return nil, fmt.Errorf("unclosed quote in command")
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args, nil
}

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
	parts, err := splitCommandArgs(cmd)
	if err != nil {
		return policy.ToolRequest{}, err
	}
	if len(parts) == 0 {
		return policy.ToolRequest{}, fmt.Errorf("empty command")
	}
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

// validateAPIRootfs constrains the caller-supplied rootfs of the legacy
// /api/containers/start endpoint. The value is interpolated verbatim into the
// UML kernel command line (ubd0=<path>) and the kernel re-splits argv on
// whitespace, so anything but a plain absolute path inside the image root is
// an injection primitive (extra kernel parameters, another task's disk, ...).
// It returns the symlink-RESOLVED trusted path for the caller to use.
func validateAPIRootfs(rootfs string) (string, error) {
	return validateRootfsUnder(rootfs, image.DefaultDir)
}

// validateRootfsUnder is validateAPIRootfs with an injectable root, so the
// symlink-resolution semantics are testable without the (root-owned)
// production image dir. Error messages name the given root.
func validateRootfsUnder(rootfs, root string) (string, error) {
	if rootfs == "" {
		return "", errors.New("rootfs is required")
	}
	if strings.ContainsAny(rootfs, " \t\n\r,") || strings.Contains(rootfs, ":") {
		return "", errors.New("rootfs must not contain whitespace, comma, or colon")
	}
	if !filepath.IsAbs(rootfs) {
		return "", errors.New("rootfs must be an absolute path")
	}
	clean := filepath.Clean(rootfs)
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return "", errors.New("rootfs must not contain '..'")
		}
	}
	// Resolve symlinks on BOTH sides BEFORE the containment check and return
	// the resolved path. A raw-string prefix check would accept a symlinked
	// rootfs name that later re-resolves elsewhere (symlink-swap window
	// between validation and use); handing the caller the resolved trusted
	// path closes that window — buildLegacyArgs/validateRootfs operate on
	// exactly what was checked.
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("rootfs %s does not resolve: %w", clean, err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("image dir %s does not resolve: %w", root, err)
	}
	if resolved != resolvedRoot && !strings.HasPrefix(resolved, resolvedRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("rootfs must live under %s", root)
	}
	return resolved, nil
}

// taskTransitionMu gives per-task mutual exclusion for the /transition
// endpoint (and any other handler that does LoadState -> mutate -> SaveState).
// Without it, two concurrent transitions on the same task each load the same
// stale state and the second SaveState silently clobbers the first's
// transition. Different tasks still proceed in parallel.
var (
	taskTransitionMu    sync.Mutex
	taskTransitionLocks = map[string]*taskLockEntry{}
)

// taskLockEntry couples a per-task mutex with its holder count so the map
// entry is deleted once the last holder releases — long-running servers with
// many short tasks would otherwise grow the map forever.
type taskLockEntry struct {
	mu      sync.Mutex
	holders int
}

// taskLock acquires the mutex guarding transitions for id and returns a
// release function. The outer mutex is held only briefly to look up / create
// the entry and bump its holder count; the last releaser deletes the entry.
func taskLock(id string) (release func()) {
	taskTransitionMu.Lock()
	entry, ok := taskTransitionLocks[id]
	if !ok {
		entry = &taskLockEntry{}
		taskTransitionLocks[id] = entry
	}
	entry.holders++
	taskTransitionMu.Unlock()
	entry.mu.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			entry.mu.Unlock()
			taskTransitionMu.Lock()
			entry.holders--
			if entry.holders == 0 {
				delete(taskTransitionLocks, id)
			}
			taskTransitionMu.Unlock()
		})
	}
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
