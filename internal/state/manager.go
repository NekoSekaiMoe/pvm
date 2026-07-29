package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ContainerState struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

func SaveState(containerID string, state *ContainerState) error {
	dir := filepath.Join("/var/lib/uml-container/containers", containerID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, "state.json"), data, 0644)
}

func LoadState(containerID string) (*ContainerState, error) {
	data, err := os.ReadFile(filepath.Join("/var/lib/uml-container/containers", containerID, "state.json"))
	if err != nil {
		return nil, err
	}
	var state ContainerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state json: %v", err)
	}
	return &state, nil
}
