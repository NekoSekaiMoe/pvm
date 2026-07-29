package uml

import (
	"context"
	"os"
	"os/exec"
)

// Launcher defines how to launch a UML kernel.
type Launcher interface {
	Launch(ctx context.Context, kernel string, args []string, logFile *os.File) error
}

type DefaultLauncher struct{}

func (l *DefaultLauncher) Launch(ctx context.Context, kernel string, args []string, logFile *os.File) error {
	cmd := exec.CommandContext(ctx, kernel, args...)
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}
