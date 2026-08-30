package uml

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"uml-container/internal/jail"
)

type ContextKey string

const (
	KeyJailEnv ContextKey = "jail_env"
	// KeyConsoleTee carries an optional io.Writer (a console.Session) that
	// receives a copy of every guest stdout/stderr byte alongside the console
	// log file. This is how the console exec/PTY layer observes guest output
	// without touching the copy-to-log path.
	KeyConsoleTee ContextKey = "console_tee"
	// KeyStdoutWriter / KeyStderrWriter carry optional per-stream writers
	// (e.g. separate rotating console.out.log / console.err.log). When set
	// they REPLACE the plain logFile for that stream; the logFile still
	// receives the combined stream, preserving console.log semantics.
	KeyStdoutWriter ContextKey = "stdout_writer"
	KeyStderrWriter ContextKey = "stderr_writer"
	// KeyExtraFiles carries host-side pre-opened files (tap fd, ...) that
	// must be inherited by the workload. Entry i becomes fd 3+i in the
	// direct child (os/exec.ExtraFiles contract) and survives the jail
	// helper's exec into the workload, so kernel args can reference fd=3+i.
	// This is the rootless-jail mechanism for moving privileged opens
	// (TUNSETIFF) host-side (TODO.md "[P1] Jail rootless 化"). Ownership
	// transfers to the launcher: all ExtraFiles are closed after Start
	// (the child holds its own duplicates) — do not use them afterwards.
	KeyExtraFiles ContextKey = "extra_files"
)

// Process is the handle returned by Launcher.Start. It pairs the underlying
// exec.Cmd with a WaitGroup that completes once all stdout/stderr copy
// goroutines have finished draining the pipes. Callers must use
// Launcher.Wait(*Process) instead of cmd.Wait() directly so the console log
// is not truncated when the process exits.
type Process struct {
	Cmd *exec.Cmd
	wg  sync.WaitGroup
	// Stdin is the host-side write end of the guest console stdin pipe,
	// non-nil only when the launcher owns the console (logFile mode). It is
	// consumed by the console session layer; closing it signals EOF to the
	// guest exactly like a detached terminal.
	Stdin io.WriteCloser
}

// Launcher defines how to launch a UML kernel.
type Launcher interface {
	Start(ctx context.Context, kernel string, args []string, log io.Writer) (int, *Process, error)
	Wait(p *Process) error
}

type DefaultLauncher struct{}

func (l *DefaultLauncher) Start(ctx context.Context, kernel string, args []string, log io.Writer) (int, *Process, error) {
	cmd := exec.CommandContext(ctx, kernel, args...)
	if files, ok := ctx.Value(KeyExtraFiles).([]*os.File); ok && len(files) > 0 {
		cmd.ExtraFiles = files
	}
	if jEnv, ok := ctx.Value(KeyJailEnv).(*jail.JailEnvironment); ok && jEnv != nil {
		// A failed isolation setup must abort BEFORE cmd.Start: running the
		// kernel without the promised sandbox would silently violate the
		// jail contract. Returning the error lets the caller (container
		// Manager) flip the task state to Failed instead of Running.
		if err := jail.ConfigureProcessIsolation(cmd, jEnv); err != nil {
			return 0, nil, fmt.Errorf("uml: configure process isolation: %w", err)
		}
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

	if log != nil {
		// Console ownership mode: guest stdin becomes a pipe the host can
		// write marker/exec scripts into, and output fans out to both the
		// console log and the optional console session tee.
		stdin, serr := cmd.StdinPipe()
		if serr != nil {
			return 0, nil, serr
		}
		p.Stdin = stdin
		var out, errW io.Writer = log, log
		if tee, ok := ctx.Value(KeyConsoleTee).(io.Writer); ok && tee != nil {
			out = io.MultiWriter(out, tee)
			errW = io.MultiWriter(errW, tee)
		}
		if w, ok := ctx.Value(KeyStdoutWriter).(io.Writer); ok && w != nil {
			out = io.MultiWriter(w, out)
		}
		if w, ok := ctx.Value(KeyStderrWriter).(io.Writer); ok && w != nil {
			errW = io.MultiWriter(w, errW)
		}
		p.wg.Add(2)
		go copyLine(out, stdout)
		go copyLine(errW, stderr)
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
		closeExtraFiles(cmd)
		return 0, nil, err
	}
	// The child holds its own duplicates of every ExtraFiles entry (tap fd,
	// jail hand-over fds); close the manager-side copies so they don't leak
	// across many launches. Callers must not use their copies after Start.
	closeExtraFiles(cmd)
	return cmd.Process.Pid, p, nil
}

// closeExtraFiles releases the parent-side copies of cmd.ExtraFiles.
func closeExtraFiles(cmd *exec.Cmd) {
	for _, f := range cmd.ExtraFiles {
		_ = f.Close()
	}
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
