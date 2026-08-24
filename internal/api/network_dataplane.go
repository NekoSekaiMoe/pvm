package api

// Bridgeless TC/eBPF data plane endpoints (todo.md P2). The dataplanes
// themselves are attached by container.StartTask when a spec sets
// network.dataplane = "tc" and live in the process-local network registry;
// these handlers expose them read-only over REST. Rule mutation is NOT
// offered here: policy writes stay on the P1-A whitelist CLI / dnslearn API.

import (
	"net/http"

	"uml-container/internal/network"

	"github.com/labstack/echo/v4"
)

// registerDataplaneRoutes wires the P2 dataplane status endpoints. Called
// from NewE2BServer; all routes sit behind the /api Bearer auth.
func registerDataplaneRoutes(api *echo.Group) {
	// Global view: every task with an attached tc dataplane plus the shared
	// pvm-gw gateway device posture. Bridge-mode tasks never appear (the
	// registry only holds tc attachments); mode_default records that.
	api.GET("/network/dataplane", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"mode_default": "bridge",
			"gw_device":    network.GwDeviceStatus(),
			"tasks":        network.DataplaneStatus(),
		})
	})

	// Per-task detail: fixed addressing, attached programs, map pin dir,
	// session count and drop/forward counters.
	api.GET("/network/dataplane/:task", func(c echo.Context) error {
		task := c.Param("task")
		if !idRegex.MatchString(task) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		}
		st, ok := network.DataplaneStatusFor(task)
		if !ok {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "no tc dataplane registered for task (dataplane!=tc, attach degraded, or task not running)",
			})
		}
		return c.JSON(http.StatusOK, st)
	})
}
