package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"uml-container/internal/state"
)

func b64decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// mkdirTaskState seeds a task state record for envd tests.
func mkdirTaskState(t *testing.T, id, status string) {
	t.Helper()
	dir := filepath.Join(state.RootDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stateJSON := `{"id":"` + id + `","name":"` + id + `","status":"` + status + `","pid":99999}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(stateJSON), 0o600); err != nil {
		t.Fatal(err)
	}
}

func envdTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	oldRoot := state.RootDir
	state.RootDir = t.TempDir()
	t.Cleanup(func() { state.RootDir = oldRoot })
	t.Setenv("PVM_EXEC_SIM", "1")
	t.Setenv("PVM_ENVD_PORT", "0")
	mux := http.NewServeMux()
	mux.HandleFunc("/process.Process/", envdProcess)
	mux.HandleFunc("/filesystem.Filesystem/", envdFilesystem)
	mux.HandleFunc("/files", envdRawFiles)
	return mux
}

func mustTask(t *testing.T) string {
	t.Helper()
	id := "t-envd"
	mkdirTaskState(t, id, "running")
	return id
}

func envdPost(t *testing.T, mux *http.ServeMux, path string, body []byte, hdr map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Result()
}

func TestEnvdProcessStartSim(t *testing.T) {
	mux := envdTestMux(t)
	task := mustTask(t)

	payload, _ := json.Marshal(map[string]interface{}{
		"process": map[string]interface{}{"cmd": "/bin/bash", "args": []string{"-l", "-c", "echo hi"}},
		"stdin":   false,
	})
	resp := envdPost(t, mux, "/process.Process/Start", envdEncodeEnvelope(payload, 0),
		map[string]string{"Content-Type": "application/connect+json", "X-Task-Id": task})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	br := bufio.NewReader(resp.Body)
	var sawEnd, sawEOS bool
	stdout := ""
	for {
		flags, frame, err := envdReadEnvelope(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if flags&connectEndStreamFlag != 0 {
			sawEOS = true
			break
		}
		var ev struct {
			Event struct {
				Data struct {
					Stdout string `json:"stdout"`
				} `json:"data"`
				End struct {
					ExitCode int `json:"exitCode"`
				} `json:"end"`
			} `json:"event"`
		}
		if err := json.Unmarshal(frame, &ev); err != nil {
			continue
		}
		if ev.Event.Data.Stdout != "" {
			dec, _ := b64decode(ev.Event.Data.Stdout)
			stdout += string(dec)
		}
		if ev.Event.End.ExitCode == 0 {
			sawEnd = true
		}
	}
	if !sawEnd || !sawEOS {
		t.Fatalf("missing end/eos frames: end=%v eos=%v", sawEnd, sawEOS)
	}
	if !strings.Contains(stdout, "simulated") {
		t.Fatalf("sim stdout missing: %q", stdout)
	}
}

func TestEnvdFilesystemAndRawFiles(t *testing.T) {
	mux := envdTestMux(t)
	task := mustTask(t)
	hdr := map[string]string{"X-Task-Id": task}

	// makeDir + list + stat + move + remove round trip.
	resp := envdPost(t, mux, "/filesystem.Filesystem/MakeDir", []byte(`{"path":"sub"}`), hdr)
	if resp.StatusCode != 200 {
		t.Fatalf("MakeDir %d", resp.StatusCode)
	}
	resp = envdPost(t, mux, "/filesystem.Filesystem/ListDir", []byte(`{"path":"."}`), hdr)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"sub"`) {
		t.Fatalf("ListDir must show sub: %s", body)
	}

	// Raw write + read.
	req := httptest.NewRequest(http.MethodPost, "/files?path=sub/a.txt&username=root", strings.NewReader("payload"))
	req.Header.Set("X-Task-Id", task)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("raw write %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/files?path=sub/a.txt&username=root", nil)
	req.Header.Set("X-Task-Id", task)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "payload" {
		t.Fatalf("raw read = %q", rec.Body.String())
	}

	// Stat via fenced path.
	resp = envdPost(t, mux, "/filesystem.Filesystem/Stat", []byte(`{"path":"sub/a.txt"}`), hdr)
	body, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"a.txt"`) {
		t.Fatalf("Stat: %s", body)
	}

	// Traversal is neutralized: Clean() folds ../../ into the workspace,
	// so the lookup lands on a NON-EXISTENT in-workspace path (404) and
	// never touches the host's /etc/passwd.
	resp = envdPost(t, mux, "/filesystem.Filesystem/Stat", []byte(`{"path":"../../etc/passwd"}`), hdr)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("traversal must be neutralized to 404, got %d", resp.StatusCode)
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Fatalf("host /etc/passwd must be untouched: %v", err)
	}
}

func TestEnvdVersionWSHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			envdVersionWS(rec, req)
			c.Write(rec.Body.Bytes()) // not used; real path hijacks
			c.Close()
		}
	}()
	// Drive the handler through a real hijackable server instead.
	ts := httptest.NewServer(http.HandlerFunc(envdVersionWS))
	defer ts.Close()

	// wsKey is the RFC6455 sample key.
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		t.Fatalf("handshake failed: %q %v", line, err)
	}
	// Drain headers.
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}
	// First data frame must be the version JSON.
	op, payload, err := readWSFrame(br)
	if err != nil {
		t.Fatal(err)
	}
	if op != 0x1 || !strings.Contains(string(payload), `"envd"`) {
		t.Fatalf("version frame wrong: op=%d %s", op, payload)
	}
}

func TestEnvdWatchDirEmitsEvents(t *testing.T) {
	mux := envdTestMux(t)
	task := mustTask(t)

	// Start the watch in a recorder; the handler streams until ctx done.
	req := httptest.NewRequest(http.MethodPost, "/filesystem.Filesystem/WatchDir", strings.NewReader(`{"path":"."}`))
	req.Header.Set("X-Task-Id", task)
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()

	// Wait for the watcher to arm, then create a file in the workspace.
	time.Sleep(700 * time.Millisecond)
	ws, err := taskWorkspace(task)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(ws+"/newfile.txt", []byte("x"), 0o644)
	<-done

	out := rec.Body.Bytes()
	found := false
	br := bytes.NewReader(out)
	for {
		_, frame, err := envdReadEnvelope(br)
		if err != nil {
			break
		}
		if strings.Contains(string(frame), "newfile.txt") {
			found = true
		}
	}
	if !found {
		t.Fatalf("watch must emit CHANGED for newfile.txt: %s", out)
	}
}
