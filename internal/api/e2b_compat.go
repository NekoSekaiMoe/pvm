// E2B SDK compatibility surface (todo #1).
//
// The official E2B SDKs (JS @e2b/sdk, Python e2b) speak a small REST contract
// at the API host ROOT — not under /api:
//
//	GET    /sandboxes                        list sandboxes
//	POST   /sandboxes                        create sandbox
//	DELETE /sandboxes/{sandboxID}            kill sandbox
//	POST   /sandboxes/{sandboxID}/refreshes  keep-alive {duration} seconds
//
// They authenticate with the X-API-KEY header and build the base URL as
// https://api.{E2B_DOMAIN} — or http://localhost:3000 when E2B_DEBUG is set
// (that is the hook the SDK test in tests/10_test_e2b_sdk.sh uses). Error
// bodies must carry {"message": ...}: the SDKs surface that field verbatim.
//
// Scope: these routes make list/kill/refresh drivable by a real E2B SDK
// against PVM. Full lifecycle compatibility additionally requires an
// envd-compatible daemon inside the guest (the SDK's create() waits for a
// WebSocket on port 49982 before reporting the sandbox ready); that is
// deliberately out of scope here. The legacy /api surface is unchanged.

package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/lifecycle"
	"uml-container/internal/snapshot"
	"uml-container/internal/state"
)

// e2bCompatKeyAuth authenticates the /sandboxes group. Unlike the /api
// KeyAuth middleware (Authorization header), it accepts BOTH headers the
// ecosystem uses: X-API-KEY (official SDKs) and Authorization: Bearer (curl /
// PVM's own conventions). Comparison stays constant-time for the same reason
// as the /api middleware.
func e2bCompatKeyAuth(apiSecretBytes []byte) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := c.Request().Header.Get("X-API-KEY")
			if key == "" {
				auth := c.Request().Header.Get("Authorization")
				key = strings.TrimPrefix(auth, "Bearer ")
			}
			if subtle.ConstantTimeCompare([]byte(key), apiSecretBytes) == 1 {
				c.Set("actor", "e2b-sdk")
				return next(c)
			}
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "unauthenticated"})
		}
	}
}

// e2bSandboxView is one entry of GET /sandboxes. Field names are camelCase
// exactly as the SDKs read them (sandboxID, clientID, templateID, cpuCount,
// memoryMB, startedAt); alias/metadata are omitted when empty, matching the
// SDKs' conditional spread.
type e2bSandboxView struct {
	SandboxID  string            `json:"sandboxID"`
	ClientID   string            `json:"clientID"`
	TemplateID string            `json:"templateID"`
	CPUCount   int               `json:"cpuCount"`
	MemoryMB   int64             `json:"memoryMB"`
	Alias      string            `json:"alias,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	StartedAt  time.Time         `json:"startedAt"`
}

// resolveSandboxID maps the ID the SDK sends to a PVM task ID. E2B SDKs call
// kill with `fullID.split("-")[0]` — the segment BEFORE the first dash — so a
// PVM id containing dashes ("web-container") arrives truncated ("web").
// Resolution: exact match first, then unique prefix match; no match is 404,
// an ambiguous prefix is 409.
func resolveSandboxID(shortID string) (string, error) {
	all, err := state.ListAll()
	if err != nil {
		return "", err
	}
	var matches []string
	for _, st := range all {
		// An exact ID always wins, even when it is also a prefix of other
		// task IDs — otherwise killing "web" would 409 just because
		// "web-container" exists.
		if st.ID == shortID {
			return st.ID, nil
		}
		if strings.HasPrefix(st.ID, shortID) {
			matches = append(matches, st.ID)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", os.ErrNotExist
	default:
		return "", fmt.Errorf("sandbox prefix %q is ambiguous: %v", shortID, matches)
	}
}

// registerE2BCompat wires the SDK-facing routes onto the echo instance at the
// host root. autoMgr mirrors the legacy start handler's lifecycle wiring.
func registerE2BCompat(e *echo.Echo, apiSecretBytes []byte, autoMgr *lifecycle.Manager) {
	// Register each route directly on the Echo instance with the auth
	// middleware passed per route. An e.Group("", auth) would make Echo's
	// Group.Use register catch-all RouteNotFound handlers ("" and "/*")
	// wrapped with the group middleware, so unauthenticated WebUI SPA
	// fallback requests would be intercepted with a 401 instead of being
	// served index.html.
	auth := e2bCompatKeyAuth(apiSecretBytes)

	// GET /sandboxes — list all tasks in SDK shape.
	e.GET("/sandboxes", func(c echo.Context) error {
		all, err := state.ListAll()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
		}
		views := make([]e2bSandboxView, 0, len(all))
		for _, st := range all {
			views = append(views, e2bSandboxView{
				SandboxID:  st.ID,
				ClientID:   "",
				TemplateID: st.Name,
				Metadata:   st.Metadata,
				StartedAt:  st.StartedAt,
			})
		}
		return c.JSON(http.StatusOK, views)
	}, auth)

	// POST /sandboxes — create (boot) a sandbox from a templateID, which maps
	// to PVM's rootfs concept. Mirrors POST /api/containers/start's validation
	// and launch path; without a UML kernel (CI) launch fails and surfaces as
	// E2B's "server error" (500 + message), which the SDKs report cleanly.
	e.POST("/sandboxes", func(c echo.Context) error {
		var req struct {
			TemplateID string            `json:"templateID"`
			Metadata   map[string]string `json:"metadata"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
		}
		if strings.TrimSpace(req.TemplateID) == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "templateID is required"})
		}
		resolvedRootfs, err := validateAPIRootfs(req.TemplateID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
		}

		name := "sbx" + strconv.FormatInt(time.Now().UTC().UnixNano()%1e12, 10)
		memBytes, err := config.ParseMemory("512M")
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
		}
		mgr := container.NewManager(nil)
		mgr.Autopause = autoMgr
		cfg := &config.ContainerConfig{
			ID:          name,
			Name:        name,
			Rootfs:      resolvedRootfs,
			Kernel:      "./bin/linux",
			Init:        "/init.sh",
			Memory:      strconv.FormatInt(memBytes, 10),
			MemoryBytes: memBytes,
		}
		// Boot — not Start: Start blocks in Launcher.Wait until the UML
		// process exits, which would hang the create call for the sandbox's
		// whole lifetime. Use a background context: the request context is
		// cancelled as soon as this handler returns, and exec.CommandContext
		// would kill the just-booted kernel.
		b, err := mgr.Boot(context.Background(), cfg)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
		}
		// Persist SDK metadata into the task state so GET /sandboxes can
		// reflect it back (E2B metadata is a create-time label set).
		if len(req.Metadata) > 0 {
			st, lerr := state.LoadState(name)
			if lerr != nil {
				// Boot persisted state moments ago; failing to reload it
				// means the state dir is broken. Do not report create
				// success for a sandbox whose metadata cannot be persisted:
				// tear it down (kill + synchronous reap + remove) instead
				// of leaving an orphaned VM behind.
				teardownBootedSandbox(mgr, name, b)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"message": fmt.Sprintf("sandbox started but state reload failed; sandbox rolled back: %v", lerr),
				})
			}
			st.Metadata = req.Metadata
			if serr := state.SaveState(name, st); serr != nil {
				go func() { _ = mgr.WaitExit(name, b) }()
				return c.JSON(http.StatusInternalServerError, map[string]string{"message": serr.Error()})
			}
		}
		// Reap the process and record the terminal status in the background
		// so the create response can return immediately after startup.
		go func() { _ = mgr.WaitExit(name, b) }()
		return c.JSON(http.StatusOK, map[string]string{
			"sandboxID":  name,
			"clientID":   "",
			"templateID": req.TemplateID,
		})
	}, auth)

	// DELETE /sandboxes/:sandboxID — kill + remove, mirroring the semantics
	// of DELETE /api/containers/:id (PID-reuse-checked process kill, clone
	// guard via snapshot.PrepareDelete, directory removal).
	e.DELETE("/sandboxes/:sandboxID", func(c echo.Context) error {
		shortID := c.Param("sandboxID")
		if !idRegex.MatchString(shortID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "invalid sandbox ID"})
		}
		id, err := resolveSandboxID(shortID)
		if errors.Is(err, os.ErrNotExist) {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "sandbox not found"})
		}
		if err != nil {
			return c.JSON(http.StatusConflict, map[string]string{"message": err.Error()})
		}

		// Serialize against a concurrent refresh of the same sandbox: the
		// refresh handler rewrites state.json, so a delete racing it would
		// resurrect a just-killed sandbox on disk.
		release := taskLock(id)
		defer release()

		// Kill the process if it is really still ours (PID may be reused).
		st, err := state.LoadState(id)
		if err == nil && st.PID > 0 {
			if proc, perr := os.FindProcess(st.PID); perr == nil {
				if belongs, _ := procBelongsToContainer(st.PID, id); belongs {
					if killErr := proc.Kill(); killErr != nil && killErr.Error() != "os: process already finished" {
						return c.JSON(http.StatusInternalServerError, map[string]string{
							"message": fmt.Sprintf("failed to kill process %d: %v", st.PID, killErr),
						})
					}
				}
			}
		}

		dir, err := state.ContainerDir(id)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
		}
		if err := snapshot.PrepareDelete(id); err != nil {
			if errors.Is(err, snapshot.ErrHasClones) {
				return c.JSON(http.StatusConflict, map[string]string{"message": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
		}
		if err := os.RemoveAll(dir); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"message": fmt.Sprintf("failed to remove sandbox directory: %v", err),
			})
		}
		return c.JSON(http.StatusOK, map[string]string{"message": "killed"})
	}, auth)

	// POST /sandboxes/:sandboxID/refreshes — keep-alive: push the task's
	// Deadline out by `duration` seconds (the SDKs cap at 3600; enforce the
	// same bound server-side).
	e.POST("/sandboxes/:sandboxID/refreshes", func(c echo.Context) error {
		shortID := c.Param("sandboxID")
		if !idRegex.MatchString(shortID) {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "invalid sandbox ID"})
		}
		var req struct {
			Duration int64 `json:"duration"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": err.Error()})
		}
		if req.Duration < 0 || req.Duration > 3600 {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "duration must be between 0 and 3600 seconds"})
		}
		id, err := resolveSandboxID(shortID)
		if errors.Is(err, os.ErrNotExist) {
			return c.JSON(http.StatusNotFound, map[string]string{"message": "sandbox not found"})
		}
		if err != nil {
			return c.JSON(http.StatusConflict, map[string]string{"message": err.Error()})
		}
		// Same per-sandbox lock as DELETE: the LoadState/SaveState pair below
		// must not interleave with a concurrent delete of this sandbox.
		release := taskLock(id)
		defer release()
		st, err := state.LoadState(id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
		}
		st.Deadline = time.Now().UTC().Add(time.Duration(req.Duration) * time.Second)
		if err := state.SaveState(id, st); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"message": "ok"})
	}, auth)
}

// teardownBootedSandbox kills a just-booted sandbox whose create must fail,
// reaps it synchronously (no background reaper owns the process yet), and
// removes its state directory. Best-effort: the create is already failing.
func teardownBootedSandbox(mgr *container.Manager, id string, b *container.Booted) {
	if b != nil && b.Process != nil && b.Process.Cmd != nil && b.Process.Cmd.Process != nil {
		_ = b.Process.Cmd.Process.Kill()
	}
	_ = mgr.WaitExit(id, b)
	if dir, err := state.ContainerDir(id); err == nil {
		_ = os.RemoveAll(dir)
	}
}
