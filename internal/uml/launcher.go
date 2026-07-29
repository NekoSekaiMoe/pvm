package uml

import (
	"context"
	"io"
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
	// Use pipes for stdout/stderr to prevent UML epoll_ctl errors on regular files
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	
	if logFile != nil {
		go io.Copy(logFile, stdout)
		go io.Copy(logFile, stderr)
	} else {
		cmd.Stdin = os.Stdin
		go io.Copy(os.Stdout, stdout)
		go io.Copy(os.Stderr, stderr)
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
