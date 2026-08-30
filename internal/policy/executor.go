package policy

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"uml-container/internal/console"
)

// ConsoleExecutor builds a host-side Executor that runs tool commands inside
// the task's guest console via the marker protocol (see internal/console).
// taskID binds the executor to one task (the gateway registers per task).
//
// Tool semantics: when Args carries a "cmd" string it is executed verbatim
// (e.g. `bash -lc '...'`); otherwise the tool name itself runs as the
// command. Output is capped in the summary; the full exit code and duration
// ride in Result. Secrets scrubbing happens in the gateway's sanitize step.
func ConsoleExecutor(taskID string, sessFn func(taskID string) (*console.Session, error)) func(req ToolRequest) (ToolResponse, error) {
	return func(req ToolRequest) (ToolResponse, error) {
		sess, err := sessFn(taskID)
		if err != nil {
			return ToolResponse{}, fmt.Errorf("policy: console executor: %w", err)
		}
		cmd, _ := req.Args["cmd"].(string)
		if cmd == "" {
			cmd = req.Name
		}
		res, err := sess.Exec(context.Background(), cmd, execTimeout())
		if err != nil {
			return ToolResponse{OK: false, Reason: err.Error()}, err
		}
		summary := strings.TrimSpace(res.Stdout)
		if len(summary) > 400 {
			summary = summary[:400] + "…"
		}
		return ToolResponse{
			OK:      res.ExitCode == 0,
			Summary: summary,
			Result: map[string]interface{}{
				"exit_code":    res.ExitCode,
				"duration_ms":  res.Duration.Milliseconds(),
				"output_bytes": len(res.Stdout),
				"simulated":    false,
			},
		}, nil
	}
}

func execTimeout() time.Duration {
	if v := os.Getenv("PVM_EXEC_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 30 * time.Second
}

// SimExecutor returns an executor that never touches a guest: it echoes a
// structured simulated result. This exists so CI-safe tests can exercise the
// full gateway→approval→execution pipeline and so operators can rehearse
// workflows on hosts without a kernel. Enable explicitly with PVM_EXEC_SIM=1;
// every simulated execution is audited as such (never presented as real).
func SimExecutor() func(req ToolRequest) (ToolResponse, error) {
	return func(req ToolRequest) (ToolResponse, error) {
		return ToolResponse{
			OK:      true,
			Summary: fmt.Sprintf("%s: simulated execution (PVM_EXEC_SIM)", req.Name),
			Result: map[string]interface{}{
				"exit_code": 0,
				"simulated": true,
			},
		}, nil
	}
}
