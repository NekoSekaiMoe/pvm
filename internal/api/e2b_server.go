package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type ExecRequest struct {
	Command string `json:"cmd"`
}

type ExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

// StartE2BServer starts a REST API compatible with E2B SDK
func StartE2BServer(port int) error {
	http.HandleFunc("/exec", func(w http.ResponseWriter, r *http.Request) {
		var req ExecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// In a full implementation, this sends the command to the UML guest via a serial socket or vsock.
		// For MVP, we mock the execution response to demonstrate SDK compatibility.
		fmt.Printf("[API] E2B SDK requested execution: %s\n", req.Command)

		resp := ExecResponse{
			Stdout:   "Execution simulated for: " + req.Command,
			Stderr:   "",
			ExitCode: 0,
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("E2B-compatible API Server listening on %s\n", addr)
	return http.ListenAndServe(addr, nil)
}
