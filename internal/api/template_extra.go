package api

// template_extra.go — snapshot→template promotion, inspection, and live
// preview endpoints.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/state"
	"uml-container/internal/template"

	"github.com/labstack/echo/v4"
)

func registerTemplateExtras(api *echo.Group, tmplStore *template.Store) {
	// POST /api/templates/from-snapshot — promote a task snapshot into a
	// READY template (flattened standalone image).
	api.POST("/templates/from-snapshot", func(c echo.Context) error {
		var req struct {
			Task       string `json:"task"`
			SnapshotID string `json:"snapshot_id"`
			Alias      string `json:"alias"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.SnapshotID == "" {
			// Without an explicit snapshot, promote the task's NEWEST one.
			ids, err := template.SnapshotIDs(req.Task)
			if err != nil || len(ids) == 0 {
				return c.JSON(http.StatusNotFound, map[string]string{"error": "task has no snapshots"})
			}
			req.SnapshotID = ids[len(ids)-1]
		}
		rec, err := template.CreateFromSnapshot(tmplStore, req.Task, req.SnapshotID, req.Alias)
		if err != nil {
			if errors.Is(err, template.ErrSnapshotNotFound) {
				return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusCreated, rec)
	})

	// GET /api/templates/:id/inspect — record + image size/hash.
	api.GET("/templates/:id/inspect", func(c echo.Context) error {
		// Record + image stats; the SHARED store keeps the alias index fresh
		// for the sibling GET routes.
		rec, err := template.Inspect(tmplStore, c.Param("id"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, template.ErrNotFound) {
				return c.JSON(http.StatusNotFound, map[string]string{"error": "template not found"})
			}
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, rec)
	})

	// POST /api/templates/:id/preview — boot an ephemeral sandbox from the
	// template and return its console output (the "does this image actually
	// work" probe). Best-effort cleanup afterwards.
	api.POST("/templates/:id/preview", func(c echo.Context) error {
		var req struct {
			Command        string `json:"command"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if err := c.Bind(&req); err != nil && !errors.Is(err, echo.ErrNotFound) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		timeout := 30 * time.Second
		if req.TimeoutSeconds > 0 {
			timeout = time.Duration(req.TimeoutSeconds) * time.Second
			if timeout > 3*time.Minute {
				timeout = 3 * time.Minute
			}
		}

		rec, err := tmplStore.Get(c.Param("id"))
		if err != nil {
			if errors.Is(err, template.ErrNotFound) {
				return c.JSON(http.StatusNotFound, map[string]string{"error": "template not found"})
			}
			return c.JSON(http.StatusNotFound, map[string]string{"error": "template not found"})
		}
		if rec.Status != "READY" || rec.ImagePath == "" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "template is not READY"})
		}
		if _, err := os.Stat("./bin/linux"); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "UML kernel not available (./bin/linux): preview requires a bootable host"})
		}

		name := fmt.Sprintf("tplpreview-%s-%d", sanitizePreviewName(rec.TemplateID), time.Now().UnixNano()%1e6)
		memBytes, _ := config.ParseMemory("256M")
		cfg := &config.ContainerConfig{
			ID:          name,
			Name:        name,
			Rootfs:      rec.ImagePath,
			Kernel:      "./bin/linux",
			Init:        "/init.sh",
			Memory:      strconv.FormatInt(memBytes, 10),
			MemoryBytes: memBytes,
			Ephemeral:   true, // read-only rootfs: preview never mutates the template
		}
		mgr := container.NewManager(nil)
		if err := mgr.Start(context.Background(), cfg); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "preview boot failed: " + err.Error()})
		}
		defer cleanupPreview(name)

		// Wait for console output (boot noise or the guest init's banner).
		dir, err := state.ContainerDir(name)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		logPath := filepath.Join(dir, "logs", "console.log")
		deadline := time.Now().Add(timeout)
		var out []byte
		for time.Now().Before(deadline) {
			if data, err := os.ReadFile(logPath); err == nil && len(strings.TrimSpace(string(data))) > 0 {
				out = data
				if len(out) > 16*1024 {
					out = out[len(out)-16*1024:]
				}
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"template_id": rec.TemplateID,
			"name":        name,
			"console":     string(out),
			"timeout":     len(out) == 0,
		})
	})
}

func sanitizePreviewName(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

// cleanupPreview kills the preview container and removes its state.
func cleanupPreview(name string) {
	if st, err := state.LoadState(name); err == nil && st.PID > 0 {
		if belongs, _ := procBelongsToContainer(st.PID, name); belongs {
			_ = syscall.Kill(st.PID, syscall.SIGKILL)
		}
	}
	if dir, err := state.ContainerDir(name); err == nil {
		_ = os.RemoveAll(dir)
	}
}
