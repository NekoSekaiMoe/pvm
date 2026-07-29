package log

import (
	"fmt"
	"os"
	"path/filepath"
	"uml-container/internal/state"
)

// SetupConsoleLog creates the log file for the container console output
func SetupConsoleLog(containerID string) (*os.File, error) {
	logDir := filepath.Join(state.ContainerDir(containerID), "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log dir: %v", err)
	}

	logFile := filepath.Join(logDir, "console.log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open console log: %v", err)
	}

	return file, nil
}
