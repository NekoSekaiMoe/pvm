package api

import (
	"encoding/json"
	"os"
	"path/filepath"

	"uml-container/internal/spec"
	"uml-container/internal/state"
)

// loadTaskSpec reads the canonical spec.json persisted by StartTask. Nil
// (and the bare gate) when the task has none (legacy containers, raw API
// sandboxes).
func loadTaskSpec(taskID string) *spec.TaskSpec {
	if taskID == "" {
		return nil
	}
	dir, err := state.ContainerDir(taskID)
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "spec.json"))
	if err != nil {
		return nil
	}
	var s spec.TaskSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return &s
}
