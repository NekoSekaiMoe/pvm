package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"uml-container/internal/state"
)

// SetupConsoleLog creates the log file for the container console output.
// The console log is the raw UML kernel/stderr stream captured into
// <state dir>/<id>/logs/console.log; it is distinct from the leveled Logger
// below (that logs the host-side process lifecycle).
func SetupConsoleLog(containerID string) (*os.File, error) {
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return nil, err
	}
	logDir := filepath.Join(dir, "logs")
	// 0700: console output can carry guest kernel messages and init output;
	// keep it private to the (root) daemon.
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create log dir: %v", err)
	}
	// MkdirAll leaves an existing dir's mode untouched — tighten it too.
	if err := os.Chmod(logDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to tighten log dir %s: %v", logDir, err)
	}

	logFile := filepath.Join(logDir, "console.log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open console log: %v", err)
	}
	// Same for a pre-existing file created with looser permissions.
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to tighten console log %s: %v", logFile, err)
	}

	return file, nil
}

// Level is the severity of a log record. Higher values are more severe.
type Level int

const (
	// LevelDebug is verbose protocol/operational detail, typically off in
	// production but indispensable for diagnosing hangs (e.g. vhost-user
	// request/reply timing).
	LevelDebug Level = iota
	// LevelInfo is normal lifecycle output (sandbox started, vhost ready).
	LevelInfo
	// LevelWarn marks unexpected but non-fatal conditions.
	LevelWarn
	// LevelError marks failures.
	LevelError
)

// String returns a 5-character upper-case label used in the log prefix.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return fmt.Sprintf("L%02d", int(l))
	}
}

// Logger is a leveled logger. It is safe for concurrent use. The zero value
// logs nothing; construct with New to pick a destination, or use Default().
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	min    Level
	prefix string
}

// Default returns the process-wide logger writing to os.Stderr at Info level.
// Use SetLevel to make it chattier (e.g. from a -debug CLI flag).
func Default() *Logger {
	return defaultLogger
}

var defaultLogger = &Logger{w: os.Stderr, min: LevelInfo}

// New returns a Logger writing to w that emits records at or above min.
func New(w io.Writer, min Level) *Logger {
	return &Logger{w: w, min: min}
}

// WithPrefix returns a copy of l whose records are tagged with prefix. It
// shares the underlying writer and minimum level. Used to tag subsystem
// output (e.g. "[vhost]").
func (l *Logger) WithPrefix(prefix string) *Logger {
	if l == nil {
		return nil
	}
	return &Logger{w: l.w, min: l.min, prefix: prefix}
}

// SetLevel sets the minimum level emitted by l. Safe to call concurrently
// with logging; callers that swap the level mid-run should treat the change
// as eventually visible.
func (l *Logger) SetLevel(min Level) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.min = min
	l.mu.Unlock()
}

// SetWriter swaps the destination writer. Useful for tests that want to
// capture output. The swap is atomic with respect to logging.
func (l *Logger) SetWriter(w io.Writer) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.w = w
	l.mu.Unlock()
}

// logf formats and writes a record at level with the standard prefix
// (timestamp, level, subsystem tag). It is the single emit path; all level
// helpers funnel through it.
func (l *Logger) logf(level Level, format string, args ...any) {
	if l == nil || level < l.currentMin() {
		return
	}
	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format("15:04:05.000")
	line := ts + " " + level.String()
	if l.prefix != "" {
		line += " " + l.prefix
	}
	line += " " + msg
	if len(msg) == 0 || msg[len(msg)-1] != '\n' {
		line += "\n"
	}
	l.mu.Lock()
	// A nil writer (zero-value Logger) emits nothing; this lets an unconfigured
	// subsystem stay quiet rather than panic on a (*Logger)(nil)-style typo.
	if l.w != nil {
		io.WriteString(l.w, line)
	}
	l.mu.Unlock()
}

func (l *Logger) currentMin() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.min
}

// Debugf logs at LevelDebug.
func (l *Logger) Debugf(format string, args ...any) { l.logf(LevelDebug, format, args...) }

// Infof logs at LevelInfo.
func (l *Logger) Infof(format string, args ...any) { l.logf(LevelInfo, format, args...) }

// Warnf logs at LevelWarn.
func (l *Logger) Warnf(format string, args ...any) { l.logf(LevelWarn, format, args...) }

// Errorf logs at LevelError.
func (l *Logger) Errorf(format string, args ...any) { l.logf(LevelError, format, args...) }

// ParseLevel maps a CLI string ("debug"/"info"/"warn"/"error") to a Level.
// Unknown strings default to LevelInfo so a typo never silences the process.
func ParseLevel(s string) Level {
	switch s {
	case "debug", "DEBUG", "Debug":
		return LevelDebug
	case "warn", "WARN", "Warn", "warning", "WARNING":
		return LevelWarn
	case "error", "ERROR", "Error":
		return LevelError
	default:
		return LevelInfo
	}
}
