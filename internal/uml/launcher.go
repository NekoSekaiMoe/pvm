package uml

import (
	"context"
	"os"
	"os/exec"
)

// Launcher defines how to launch a UML kernel.
type Launcher interface {
	Start(ctx context.Context, kernel string, args []string, logFile *os.File) (int, *exec.Cmd, error)
	Wait(cmd *exec.Cmd) error
}

type DefaultLauncher struct{}

func (l *DefaultLauncher) Start(ctx context.Context, kernel string, args []string, logFile *os.File) (int, *exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, kernel, args...)
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	} else {
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err := cmd.Start()
	if err != nil {
		return 0, nil, err
	}
	return cmd.Process.Pid, cmd, nil
}

func (l *DefaultLauncher) Wait(cmd *exec.Cmd) error {
	return cmd.Wait()
}
