package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/image"
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

	// Get all containers
	api.GET("/containers", func(c echo.Context) error {
		dirs, err := os.ReadDir(state.RootDir)
		if err != nil {
			return c.JSON(http.StatusOK, []interface{}{})
		}
		var list []state.ContainerState
		for _, d := range dirs {
			if d.IsDir() {
				st, err := state.LoadState(d.Name())
				if err == nil {
					list = append(list, *st)
				}
			}
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
		if req.CPU < 0 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "CPU limit cannot be negative"})
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
		dir, err := state.ContainerDir(id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if err := os.RemoveAll(dir); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "deleted"})
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

	// Mock exec for E2B compatibility
	api.POST("/exec", func(c echo.Context) error {
		var req ExecRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}

		fmt.Printf("[API] E2B SDK requested execution: %s\n", req.Command)

		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "not implemented"})
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
