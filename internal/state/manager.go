package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var RootDir = "/var/lib/uml-container/containers"

func ContainerDir(id string) (string, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(id) {
		return "", fmt.Errorf("invalid container ID")
	}
	return filepath.Join(RootDir, id), nil
}

type ContainerState struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

func SaveState(containerID string, state *ContainerState) error {
	dir, err := ContainerDir(containerID)
	if err != nil {
		return err
	}
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
	dir, err := ContainerDir(containerID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return nil, err
	}
	var state ContainerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state json: %v", err)
	}
	return &state, nil
}
