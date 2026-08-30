package main

// templateCmd drives the template center from the CLI: `agentpvm template
// watch <id|alias>` streams build progress (phase + pct + log tail) from
// GET /api/templates/:id/build until the pipeline reaches a terminal phase.
// Plain text (no TUI dependency): CI logs stay readable.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// watchFrame is one polled build status snapshot.
type watchFrame struct {
	Phase   string `json:"phase"`
	Pct     int    `json:"pct"`
	LogTail string `json:"log_tail"`
	Error   string `json:"error"`
}

// watchState remembers the last frame that was rendered so the watcher
// repaints whenever phase, percent, or the log tail changes — not only on
// phase transitions (a long phase would otherwise stream updates silently).
type watchState struct {
	started bool
	phase   string
	pct     int
	tail    string
}

// changed records f and reports whether it differs from the previously
// recorded frame.
func (s *watchState) changed(f watchFrame) bool {
	c := !s.started || f.Phase != s.phase || f.Pct != s.pct || f.LogTail != s.tail
	s.started = true
	s.phase, s.pct, s.tail = f.Phase, f.Pct, f.LogTail
	return c
}

// renderBar renders the 20-cell progress bar line for f (pct clamped to
// 0..100 so a hostile server cannot panic strings.Repeat with pct > 100).
func renderBar(f watchFrame) string {
	pct := f.Pct
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := pct / 5
	bar := strings.Repeat("█", filled) + strings.Repeat("░", 20-filled)
	return fmt.Sprintf("[%s] %3d%%  %s", bar, pct, f.Phase)
}

func templateCmd(args []string) {
	if len(args) < 2 || args[0] != "watch" {
		fmt.Println("Usage: agentpvm template watch <template-id-or-alias> [--timeout 5m]")
		os.Exit(1)
	}
	ident := args[1]
	timeout := 5 * time.Minute
	for i := 2; i+1 < len(args); i++ {
		if args[i] == "--timeout" {
			if d, err := time.ParseDuration(args[i+1]); err == nil {
				timeout = d
			}
		}
	}
	base := os.Getenv("PVM_API")
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	secret, err := resolveAPISecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "template: %v\n", err)
		os.Exit(1)
	}

	deadline := time.Now().Add(timeout)
	var state watchState
	terminal := map[string]bool{"done": true, "failed": true}
	for {
		req, _ := http.NewRequest("GET", base+"/api/templates/"+ident+"/build?wait=2s", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := cliHTTPClient.Do(req)
		if err != nil {
			fmt.Printf("template watch: %v (is the API running at %s?)\n", err, base)
			os.Exit(1)
		}
		// Bound the body read: a proxy error page must not stream into the
		// watcher, and a non-2xx status must abort instead of being decoded
		// as (garbage) build status.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fmt.Printf("template watch: GET /api/templates/%s/build -> %d: %s\n", ident, resp.StatusCode, strings.TrimSpace(string(body)))
			os.Exit(1)
		}
		var st watchFrame
		if jerr := json.Unmarshal(body, &st); jerr != nil {
			fmt.Printf("template watch: bad response: %v\n", jerr)
			os.Exit(1)
		}

		if state.changed(st) {
			fmt.Println(renderBar(st))
			if st.LogTail != "" {
				for _, line := range strings.Split(strings.TrimRight(st.LogTail, "\n"), "\n") {
					fmt.Printf("    │ %s\n", line)
				}
			}
		}
		if terminal[st.Phase] {
			if st.Phase == "failed" {
				fmt.Printf("template build FAILED: %s\n", st.Error)
				os.Exit(1)
			}
			fmt.Println("template READY")
			return
		}
		if time.Now().After(deadline) {
			fmt.Printf("template watch: timeout after %s (phase %s)\n", timeout, st.Phase)
			os.Exit(1)
		}
	}
}
