package uml

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"uml-container/internal/jail"
)

type ContextKey string

const (
	KeyJailEnv ContextKey = "jail_env"
)

// Process is the handle returned by Launcher.Start. It pairs the underlying
// exec.Cmd with a WaitGroup that completes once all stdout/stderr copy
// goroutines have finished draining the pipes. Callers must use
// Launcher.Wait(*Process) instead of cmd.Wait() directly so the console log
// is not truncated when the process exits.
type Process struct {
	Cmd *exec.Cmd
	wg  sync.WaitGroup
}

// Launcher defines how to launch a UML kernel.
type Launcher interface {
	Start(ctx context.Context, kernel string, args []string, logFile *os.File) (int, *Process, error)
	Wait(p *Process) error
}

type DefaultLauncher struct{}

func (l *DefaultLauncher) Start(ctx context.Context, kernel string, args []string, logFile *os.File) (int, *Process, error) {
	cmd := exec.CommandContext(ctx, kernel, args...)
	if jEnv, ok := ctx.Value(KeyJailEnv).(*jail.JailEnvironment); ok && jEnv != nil {
		_ = jail.ConfigureProcessIsolation(cmd, jEnv)
	}
	// Use pipes for stdout/stderr to prevent UML epoll_ctl errors on regular files
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, nil, err
	}

	p := &Process{Cmd: cmd}

	copyLine := func(dst io.Writer, src io.Reader) {
		defer p.wg.Done()
		io.Copy(dst, src)
	}

	if logFile != nil {
		p.wg.Add(2)
		go copyLine(logFile, stdout)
		go copyLine(logFile, stderr)
	} else {
		cmd.Stdin = os.Stdin
		p.wg.Add(2)
		go copyLine(os.Stdout, stdout)
		go copyLine(os.Stderr, stderr)
	}

	if err := cmd.Start(); err != nil {
		// Pipes were created; mark the goroutines we won't start as done so a
		// later Wait doesn't block forever.
		p.wg.Wait()
		return 0, nil, err
	}
	return cmd.Process.Pid, p, nil
}

// (buildCmd was previously used to optionally wrap UML under strace for hang
// diagnosis. That was removed: UML itself relies on ptrace for syscall
// interception, so running it under a ptrace-based tracer like strace makes
// UML's self-check fail with PTRACE_TRACEME EPERM and aborts boot before the
// kernel even prints its version line. Do not re-add strace here.)

func (l *DefaultLauncher) Wait(p *Process) error {
	// Per os/exec.StdoutPipe docs: wait must happen after reading is complete.
	// First drain the copy goroutines (they exit when the pipes close on
	// process exit), then call cmd.Wait to reap the process.
	p.wg.Wait()
	return p.Cmd.Wait()
}
