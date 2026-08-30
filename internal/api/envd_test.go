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

	"encoding/binary"
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

	// Seed uniquely-named probe files across the watch window: envdWatchDir
	// takes its baseline (prev := snapshot()) when the handler starts, and a
	// fixed sleep cannot prove that already happened — a file created BEFORE
	// the baseline lands in the initial state and never emits CHANGED.
	// Probes span the whole window so some are guaranteed to land after it.
	ws, err := taskWorkspace(task)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		os.WriteFile(fmt.Sprintf("%s/probe-%d.txt", ws, i), []byte("x"), 0o644)
		select {
		case <-done:
			i = 10 // stream already ended; stop seeding
		case <-time.After(100 * time.Millisecond):
		}
	}
	<-done

	out := rec.Body.Bytes()
	found := false
	br := bytes.NewReader(out)
	for {
		_, frame, err := envdReadEnvelope(br)
		if err != nil {
			break
		}
		if strings.Contains(string(frame), "CHANGED") && strings.Contains(string(frame), "probe-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("watch must emit CHANGED for a post-baseline probe file: %s", out)
	}
}

// --- fenceJoin: the workspace fence ---

func TestFenceJoin_AllowsInWorkspacePaths(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"file.txt", "sub/dir/file.txt"} {
		if _, err := fenceJoin(root, rel); err != nil {
			t.Errorf("fenceJoin(%q) unexpectedly rejected: %v", rel, err)
		}
	}
}

func TestFenceJoin_NormalizesTraversalIntoRoot(t *testing.T) {
	root := t.TempDir()
	// Lexical traversal never escapes: Clean("/..") collapses at the root,
	// so all of these map INSIDE the workspace. The fence relies on this
	// normalization; actual escapes (symlinks) are covered below.
	for _, rel := range []string{"../escape", "sub/../../escape", "/etc/passwd"} {
		p, err := fenceJoin(root, rel)
		if err != nil {
			t.Errorf("fenceJoin(%q) unexpectedly rejected: %v", rel, err)
			continue
		}
		if !strings.HasPrefix(p, root+string(filepath.Separator)) {
			t.Errorf("fenceJoin(%q) escaped: %q", rel, p)
		}
	}
}

// TestFenceJoin_RejectsSymlinkEscapeViaNewLeaf is the PR #22 review
// regression: the target file does NOT exist yet (create path), so the
// deepest EXISTING ancestor (the symlink) must be resolved and fenced —
// POST /files?path=link/new-file must not follow the link out of the root.
func TestFenceJoin_RejectsSymlinkEscapeViaNewLeaf(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := fenceJoin(root, "link/new-file"); err == nil {
		t.Fatal("creating a file through a workspace symlink pointing outside must be rejected")
	}
	// Deep chain: link/sub/dir/file must be rejected at the link too.
	if _, err := fenceJoin(root, "link/sub/dir/file"); err == nil {
		t.Fatal("nested create through an escaping symlink must be rejected")
	}
}

func TestFenceJoin_AllowsInternalSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	// Both an existing leaf through the alias and a NEW leaf under it stay
	// inside the workspace and must be allowed.
	for _, rel := range []string{"alias/keep.txt", "alias/new/deep/file.txt"} {
		if _, err := fenceJoin(root, rel); err != nil {
			t.Errorf("fenceJoin(%q) through in-root symlink unexpectedly rejected: %v", rel, err)
		}
	}
}

// --- readWSFrame: client-declared length cap ---

func TestReadWSFrame_AcceptsMaskedFrame(t *testing.T) {
	payload := []byte("hello")
	var b bytes.Buffer
	b.WriteByte(0x81) // FIN + text
	b.WriteByte(0x80 | byte(len(payload)))
	mask := [4]byte{1, 2, 3, 4} // must match the bytes written below
	b.Write(mask[:])
	masked := make([]byte, len(payload))
	for i, c := range payload {
		masked[i] = c ^ mask[i%4]
	}
	b.Write(masked)

	op, got, err := readWSFrame(bufio.NewReader(&b))
	if err != nil {
		t.Fatalf("readWSFrame: %v", err)
	}
	if op != 0x1 || !bytes.Equal(got, payload) {
		t.Fatalf("got op=%d payload=%q, want text frame %q", op, got, payload)
	}
}

func TestReadWSFrame_RejectsOversized64BitLength(t *testing.T) {
	var b bytes.Buffer
	b.WriteByte(0x82) // FIN + binary
	b.WriteByte(0x80 | 127)
	binary.Write(&b, binary.BigEndian, uint64(envdMaxWSFrame+1))
	binary.Write(&b, binary.BigEndian, uint32(0x01020304))

	if _, _, err := readWSFrame(bufio.NewReader(&b)); err == nil {
		t.Fatal("frame declaring more than envdMaxWSFrame bytes must be rejected before allocation")
	}
}

// --- envdAuth: bearer enforcement when API_SECRET is set ---

func TestEnvdAuth_RequiresBearerWhenSecretSet(t *testing.T) {
	t.Setenv("API_SECRET", "s3cret")
	called := false
	h := envdAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/process.Process/Start", nil))
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("missing bearer must 401 without touching the handler, got %d called=%v", rec.Code, called)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process.Process/Start", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	h(rec, req)
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("valid bearer must reach the handler, got %d called=%v", rec.Code, called)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process.Process/Start", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	called = false
	h(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("wrong bearer must 401, got %d", rec.Code)
	}
}

func TestEnvdAuth_OpenWhenNoSecret(t *testing.T) {
	t.Setenv("API_SECRET", "")
	h := envdAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("no-secret mode stays open (loopback binding), got %d", rec.Code)
	}
}
