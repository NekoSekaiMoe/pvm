package uml

import (
	"context"
	"os"
	"os/exec"
)

// Launcher defines how to launch a UML kernel.
type Launcher interface {
	Launch(ctx context.Context, kernel string, args []string) error
}

type DefaultLauncher struct{}

func (l *DefaultLauncher) Launch(ctx context.Context, kernel string, args []string) error {
	cmd := exec.CommandContext(ctx, kernel, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
