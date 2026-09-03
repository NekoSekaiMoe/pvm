package api

// portmap_api.go — REST surface for inbound host-port → guest mappings
// (internal/network/portmap.go). Bridge-dataplane tasks only; tc-mode
// tasks answer 409 with the typed reason.

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"uml-container/internal/network"
	"uml-container/internal/state"

	"github.com/labstack/echo/v4"
)

// portMapRequest is the POST body. guest_ip is optional: when omitted the
// task's recorded guest IP (bridge IPAM or the fixed tc address) is used.
type portMapRequest struct {
	Task      string `json:"task"`
	HostPort  int    `json:"host_port"`
	GuestPort int    `json:"guest_port"`
	GuestIP   string `json:"guest_ip"`
	Protocol  string `json:"protocol"`
}

func registerPortMapAPI(api *echo.Group) {
	api.GET("/network/portmaps", func(c echo.Context) error {
		return c.JSON(http.StatusOK, network.ListPortMappings())
	})

	api.POST("/network/portmaps", func(c echo.Context) error {
		var req portMapRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		taskID, err := resolveSandboxID(req.Task)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return c.JSON(http.StatusNotFound, map[string]string{"error": "unknown task"})
			}
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		st, err := state.LoadState(taskID)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "task state unavailable: " + err.Error()})
		}
		if st.Metadata["dataplane"] == "tc" {
			return c.JSON(http.StatusConflict, map[string]string{"error": network.ErrPortMapTCMode.Error()})
		}
		// An explicit guest_ip must match the task's recorded address: it
		// becomes the DNAT target (and a FORWARD ACCEPT subject), so a
		// free-form value would let any key holder steer host traffic to
		// an arbitrary bridge-reachable address.
		recorded := st.Metadata["guest_ip"]
		if req.GuestIP != "" && req.GuestIP != recorded {
			if recorded == "" {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "task has no recorded guest IP; explicit guest_ip is not accepted"})
			}
			return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("guest_ip %q does not match the task's recorded address %q", req.GuestIP, recorded)})
		}
		guestIP := req.GuestIP
		if guestIP == "" {
			guestIP = recorded
		}
		if guestIP == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "no guest IP recorded for the task (bridge dataplane required)"})
		}
		m := network.PortMapping{
			TaskID:    taskID,
			HostPort:  req.HostPort,
			GuestPort: req.GuestPort,
			GuestIP:   guestIP,
			Protocol:  req.Protocol,
		}
		if err := network.AddPortMapping(m); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusCreated, m)
	})

	api.DELETE("/network/portmaps/:task/:hostPort", func(c echo.Context) error {
		taskID, err := resolveSandboxID(c.Param("task"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return c.JSON(http.StatusNotFound, map[string]string{"error": "unknown task"})
			}
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		}
		hostPort, err := strconv.Atoi(c.Param("hostPort"))
		if err != nil || hostPort < 1 || hostPort > 65535 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid host port"})
		}
		proto := c.QueryParam("protocol")
		if err := network.DeletePortMapping(taskID, hostPort, proto); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return c.JSON(http.StatusNotFound, map[string]string{"error": "no such mapping"})
			}
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.NoContent(http.StatusNoContent)
	})
}
