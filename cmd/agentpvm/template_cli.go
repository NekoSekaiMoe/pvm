package main

// templateCmd drives the template center from the CLI: `agentpvm template
// watch <id|alias>` streams build progress (phase + pct + log tail) from
// GET /api/templates/:id/build until the pipeline reaches a terminal phase.
// Plain text (no TUI dependency): CI logs stay readable.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

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
	lastPhase := ""
	terminal := map[string]bool{"done": true, "failed": true}
	spnnerPos := 0
	for {
		req, _ := http.NewRequest("GET", base+"/api/templates/"+ident+"/build?wait=2s", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := cliHTTPClient.Do(req)
		if err != nil {
			fmt.Printf("template watch: %v (is the API running at %s?)\n", err, base)
			os.Exit(1)
		}
		var st struct {
			Phase   string `json:"phase"`
			Pct     int    `json:"pct"`
			LogTail string `json:"log_tail"`
			Error   string `json:"error"`
		}
		jerr := json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if jerr != nil {
			fmt.Printf("template watch: bad response: %v\n", jerr)
			os.Exit(1)
		}

		if st.Phase != lastPhase {
			bar := strings.Repeat("█", st.Pct/5) + strings.Repeat("░", 20-st.Pct/5)
			fmt.Printf("[%s] %3d%%  %s\n", bar, st.Pct, st.Phase)
			if st.LogTail != "" {
				for _, line := range strings.Split(strings.TrimRight(st.LogTail, "\n"), "\n") {
					fmt.Printf("    │ %s\n", line)
				}
			}
			lastPhase = st.Phase
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
		spnnerPos++
	}
}
