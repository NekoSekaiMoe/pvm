package api

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"uml-container/internal/state"
	"uml-container/internal/image"
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
	e.Use(middleware.CORS())

	// API Group
	api := e.Group("/api")

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
		}
		var req StartReq
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if req.Name == "" {
			req.Name = "web-container"
		}
		
		// Run umlctl start in background
		args := []string{"start", "-name", req.Name}
		if req.Rootfs != "" {
			args = append(args, "-rootfs", req.Rootfs)
		}
		if req.Mem != "" {
			args = append(args, "-mem", req.Mem)
		}
		
		cmd := exec.Command(os.Args[0], args...)
		if err := cmd.Start(); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		
		return c.JSON(http.StatusOK, map[string]string{"status": "started", "name": req.Name})
	})

	// Get logs
	api.GET("/containers/:id/logs", func(c echo.Context) error {
		id := c.Param("id")
		logPath := filepath.Join(state.ContainerDir(id), "logs", "console.log")
		data, err := os.ReadFile(logPath)
		if err != nil {
			return c.String(http.StatusNotFound, "Logs not found or container not started")
		}
		return c.String(http.StatusOK, string(data))
	})

	// Delete container
	api.DELETE("/containers/:id", func(c echo.Context) error {
		id := c.Param("id")
		os.RemoveAll(state.ContainerDir(id))
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

		resp := ExecResponse{
			Stdout:   "Execution simulated for: " + req.Command,
			Stderr:   "",
			ExitCode: 0,
		}
		return c.JSON(http.StatusOK, resp)
	})

	// Serve the embedded Nuxt UI for all other routes
	e.GET("/*", echo.WrapHandler(http.FileServer(webui.GetPublicFS())))

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("E2B-compatible API & WebUI Server listening on %s\n", addr)
	return e.Start(addr)
}
