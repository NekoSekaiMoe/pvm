package log

import (
	"bytes"
	"strings"
	"testing"
)

func newCapture(min Level) (*Logger, *bytes.Buffer) {
	var b bytes.Buffer
	return New(&b, min), &b
}

func TestLogger_LevelFiltering(t *testing.T) {
	l, b := newCapture(LevelWarn)
	l.Debugf("debug %d", 1) // filtered
	l.Infof("info %d", 2)   // filtered
	l.Warnf("warn %d", 3)   // emitted
	l.Errorf("err %d", 4)   // emitted
	out := b.String()
	if strings.Contains(out, "debug 1") {
		t.Errorf("Debug leaked at Warn level: %q", out)
	}
	if strings.Contains(out, "info 2") {
		t.Errorf("Info leaked at Warn level: %q", out)
	}
	if !strings.Contains(out, "warn 3") || !strings.Contains(out, "err 4") {
		t.Errorf("expected warn+err in output, got %q", out)
	}
}

func TestLogger_Prefix(t *testing.T) {
	l, b := newCapture(LevelInfo)
	l = l.WithPrefix("[vhost]")
	l.Infof("hello")
	out := b.String()
	if !strings.Contains(out, "[vhost] hello") {
		t.Errorf("missing prefix in %q", out)
	}
}

func TestLogger_SetLevel(t *testing.T) {
	l, b := newCapture(LevelError)
	l.Infof("before") // filtered
	l.SetLevel(LevelDebug)
	l.Debugf("after") // emitted now
	out := b.String()
	if strings.Contains(out, "before") {
		t.Errorf("'before' should have been filtered: %q", out)
	}
	if !strings.Contains(out, "after") {
		t.Errorf("'after' should be visible after level bump: %q", out)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug":   LevelDebug,
		"DEBUG":   LevelDebug,
		"info":    LevelInfo,
		"":        LevelInfo, // default
		"warn":    LevelWarn,
		"warning": LevelWarn,
		"error":   LevelError,
		"bogus":   LevelInfo, // unknown -> info
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLogger_NilSafe(t *testing.T) {
	// A nil Logger must not panic; subsystems tag logs this way.
	var l *Logger
	l.Debugf("nope")
	l.Infof("nope")
	l.SetLevel(LevelDebug)
}

func TestLogger_NewlineNormalization(t *testing.T) {
	l, b := newCapture(LevelInfo)
	l.Infof("without newline")
	l.Infof("with newline\n")
	out := b.String()
	// Each record ends with exactly one newline.
	if got := strings.Count(out, "\n"); got != 2 {
		t.Errorf("expected exactly 2 newlines, got %d in %q", got, out)
	}
}
