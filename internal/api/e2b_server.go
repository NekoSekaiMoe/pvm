package api

import (
	"fmt"
	"net/http"
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
