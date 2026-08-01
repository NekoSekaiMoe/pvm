package uml

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
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
	cmd := l.buildCmd(ctx, kernel, args, logFile)
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

// buildCmd assembles the exec.Cmd for the UML kernel. If the UML_STRACE
// environment variable is set (to any non-empty value) and strace is on PATH,
// the kernel is launched under `strace -f -o <dir>/strace.log` so a hang can be
// pinpointed to the exact syscall even when console.log is truncated by
// buffering/teardown. The strace output lands next to console.log (derived
// from logFile's directory) so existing CI log-dump logic picks it up. If
// strace is requested but missing, the launch proceeds without it and a
// warning is printed so a misconfigured tracer never silently blocks startup.
func (l *DefaultLauncher) buildCmd(ctx context.Context, kernel string, args []string, logFile *os.File) *exec.Cmd {
	if os.Getenv("UML_STRACE") != "" {
		if stracePath, err := exec.LookPath("strace"); err == nil {
			straceLog := "uml.strace.log"
			if logFile != nil && logFile.Name() != "" {
				straceLog = filepath.Join(filepath.Dir(logFile.Name()), "strace.log")
			}
			straceArgs := []string{"-f", "-o", straceLog, "-s", "512", "-tt", "--", kernel}
			straceArgs = append(straceArgs, args...)
			return exec.CommandContext(ctx, stracePath, straceArgs...)
		}
		fmt.Printf("Warning: UML_STRACE set but strace not on PATH; launching without tracer\n")
	}
	return exec.CommandContext(ctx, kernel, args...)
}

func (l *DefaultLauncher) Wait(p *Process) error {
	// Per os/exec.StdoutPipe docs: wait must happen after reading is complete.
	// First drain the copy goroutines (they exit when the pipes close on
	// process exit), then call cmd.Wait to reap the process.
	p.wg.Wait()
	return p.Cmd.Wait()
}
