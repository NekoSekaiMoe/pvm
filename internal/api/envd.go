package api

// envd.go is pvm's envd-compatible data plane (bucket-5 "E2B drop-in 最大缺
// 口"): the two E2B-conventional listeners official SDKs expect on the
// sandbox host.
//
//	:49982  websocket "envd version" service (SDK create() readiness waits
//	        for a successful ws connect; we handshake and stream one
//	        version frame, then keep the socket open and answer pings);
//	:49983  Connect-JSON RPC:
//	          POST /process.Process/Start      (enveloped, streaming events)
//	          POST /process.Process/SendStdin  (enveloped)
//	          POST /process.Process/{Kill,List,...}
//	          POST /filesystem.Filesystem/{ListDir,Stat,Remove,Move,MakeDir,WatchDir}
//	          GET/POST /files?path=&username=  (raw download/upload)
//
// Command execution routes through the console session marker protocol
// (real guest) or the explicit simulation backend (PVM_EXEC_SIM=1). File
// access is fenced to the task's host workspace dir. Enable with
// PVM_ENVD_ENABLED=1; ports via PVM_ENVD_PORT / PVM_ENVD_WS_PORT.

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"uml-container/internal/console"
	"uml-container/internal/metrics"
	"uml-container/internal/state"
)

const (
	envdDefaultPort   = 49983
	envdDefaultWSPort = 49982

	connectCompressedFlag = 0x01
	connectEndStreamFlag  = 0x02
)

var metricEnvdRequests = metrics.Counter("pvm_envd_requests_total", "envd-compat RPC requests", "method")

// StartEnvdListeners brings up the two listeners. Called by NewE2BServer
// when PVM_ENVD_ENABLED=1; errors are fatal (a half-up envd breaks SDK
// readiness worse than no envd).
func StartEnvdListeners() error {
	rpcPort := envdPortFromEnv("PVM_ENVD_PORT", envdDefaultPort)
	wsPort := envdPortFromEnv("PVM_ENVD_WS_PORT", envdDefaultWSPort)

	rpcLn, err := net.Listen("tcp", fmt.Sprintf(":%d", rpcPort))
	if err != nil {
		return fmt.Errorf("envd: rpc listen :%d: %w", rpcPort, err)
	}
	wsLn, err := net.Listen("tcp", fmt.Sprintf(":%d", wsPort))
	if err != nil {
		rpcLn.Close()
		return fmt.Errorf("envd: ws listen :%d: %w", wsPort, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/process.Process/", envdProcess)
	mux.HandleFunc("/filesystem.Filesystem/", envdFilesystem)
	mux.HandleFunc("/files", envdRawFiles)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"envd"}`)
	})
	go func() { _ = http.Serve(rpcLn, mux) }()
	go func() { _ = http.Serve(wsLn, http.HandlerFunc(envdVersionWS)) }()
	return nil
}

func envdPortFromEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var p int
		if _, err := fmt.Sscanf(v, "%d", &p); err == nil && p > 0 && p < 65536 {
			return p
		}
	}
	return def
}

// --- version websocket (:49982) ---

func envdVersionWS(w http.ResponseWriter, r *http.Request) {
	// Minimal RFC6455 server: accept the upgrade, send one version text
	// frame, then echo pings until the peer goes away.
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "not a websocket", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	accept := base64.StdEncoding.EncodeToString(sha1Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	ver, _ := json.Marshal(map[string]string{"service": "envd", "version": "0.1.0"})
	writeWSFrame(rw, 0x1, ver)
	rw.Flush()

	// Ping/pong/close loop: read frames, answer pings, exit on close/EOF.
	buf := bufio.NewReader(rw)
	for {
		opcode, payload, err := readWSFrame(buf)
		if err != nil {
			return
		}
		switch opcode {
		case 0x8: // close
			writeWSFrame(rw, 0x8, nil)
			rw.Flush()
			return
		case 0x9: // ping
			writeWSFrame(rw, 0xA, payload)
			rw.Flush()
		}
	}
}

// writeWSFrame writes one server frame (unmasked, as required for
// server->client).
func writeWSFrame(w io.Writer, opcode byte, payload []byte) {
	var head [10]byte
	head[0] = 0x80 | opcode // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		head[1] = byte(n)
		w.Write(head[:2])
	case n < 65536:
		head[1] = 126
		binary.BigEndian.PutUint16(head[2:4], uint16(n))
		w.Write(head[:4])
	default:
		head[1] = 127
		binary.BigEndian.PutUint64(head[2:10], uint64(n))
		w.Write(head[:10])
	}
	w.Write(payload)
}

// readWSFrame reads one client frame (masked).
func readWSFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	opcode = h[0] & 0x0F
	masked := h[1]&0x80 != 0
	length := int(h[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return
		}
		length = int(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}

// --- Connect envelope helpers (shared with the SDK codec) ---

func envdEncodeEnvelope(payload []byte, flags byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flags
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

func envdReadEnvelope(r io.Reader) (flags byte, payload []byte, err error) {
	var head [5]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(head[1:5])
	if n > 32<<20 {
		return 0, nil, fmt.Errorf("envd: frame too large")
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	return head[0], payload, nil
}

// --- task routing + workspace ---

func envdTaskID(r *http.Request) (string, error) {
	if t := r.Header.Get("X-Task-Id"); t != "" {
		return t, nil
	}
	if t := r.URL.Query().Get("task"); t != "" {
		return t, nil
	}
	// Default: the single live task.
	states, err := state.ListAll()
	if err != nil {
		return "", err
	}
	for _, st := range states {
		if st != nil && (st.Status == state.StatusRunning || st.Status == state.StatusReady) {
			return st.ID, nil
		}
	}
	return "", fmt.Errorf("envd: no live task (send X-Task-Id)")
}

// taskWorkspace is the host dir backing filesystem APIs for a task.
func taskWorkspace(taskID string) (string, error) {
	dir, err := state.ContainerDir(taskID)
	if err != nil {
		return "", err
	}
	ws := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		return "", err
	}
	return ws, nil
}

// fenceJoin joins rel under root, rejecting traversal and symlink escapes.
func fenceJoin(root, rel string) (string, error) {
	rel = strings.TrimPrefix(rel, "/")
	p := filepath.Join(root, filepath.Clean("/"+rel))
	if p != root && !strings.HasPrefix(p, root+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes workspace")
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		if resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			// A symlink inside the workspace pointing out: refuse.
			if rr, rerr := filepath.EvalSymlinks(root); rerr == nil && !strings.HasPrefix(resolved, rr+string(filepath.Separator)) {
				return "", fmt.Errorf("symlink escapes workspace")
			}
		}
	}
	return p, nil
}

// --- process.Process ---

func envdProcess(w http.ResponseWriter, r *http.Request) {
	method := strings.TrimPrefix(r.URL.Path, "/process.Process/")
	metricEnvdRequests.Inc("process." + method)

	task, err := envdTaskID(r)
	if err != nil {
		envdError(w, http.StatusBadRequest, err.Error())
		return
	}

	switch method {
	case "Start":
		envdProcessStart(w, r, task)
	case "SendStdin":
		envdProcessStdin(w, r, task)
	case "Kill":
		// The console exec model has no persistent pid table; a kill is
		// satisfied by detaching the session's pending waiters.
		console.Default().Detach(task)
		w.WriteHeader(http.StatusOK)
	case "List":
		writeJSONBody(w, map[string]interface{}{"processes": []interface{}{}})
	default:
		envdError(w, http.StatusNotImplemented, "process.Process/"+method+" not supported by pvm envd")
	}
}

// envdProcessStart runs one command and streams envd-shaped events.
func envdProcessStart(w http.ResponseWriter, r *http.Request, task string) {
	var req struct {
		Process struct {
			Cmd  string            `json:"cmd"`
			Args []string          `json:"args"`
			Envs map[string]string `json:"envs"`
			Cwd  string            `json:"cwd"`
		} `json:"process"`
		Stdin bool `json:"stdin"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		envdError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload := body
	// Enveloped (application/connect+json) or plain JSON both accepted.
	if len(body) >= 5 && r.Header.Get("Content-Type") == "application/connect+json" {
		if _, p, eerr := envdReadEnvelope(strings.NewReader(string(body))); eerr == nil {
			payload = p
		}
	}
	if jerr := json.Unmarshal(payload, &req); jerr != nil || req.Process.Cmd == "" {
		envdError(w, http.StatusBadRequest, "malformed process.Start request")
		return
	}
	command := req.Process.Cmd
	if len(req.Process.Args) > 0 {
		// "/bin/bash" ["-l","-c","cmd"] shape: the last arg carries the
		// payload; otherwise join args plainly.
		if len(req.Process.Args) >= 2 && req.Process.Args[len(req.Process.Args)-2] == "-c" {
			command = req.Process.Args[len(req.Process.Args)-1]
		} else {
			command = req.Process.Cmd + " " + strings.Join(req.Process.Args, " ")
		}
	}

	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/connect+json")
	w.WriteHeader(http.StatusOK)

	send := func(v any, flags byte) {
		raw, _ := json.Marshal(v)
		w.Write(envdEncodeEnvelope(raw, flags))
		if flusher != nil {
			flusher.Flush()
		}
	}

	sess, serr := console.Default().Get(task)
	switch {
	case serr == nil:
		res, eerr := sess.Exec(r.Context(), command, envdExecTimeout())
		if eerr != nil {
			send(map[string]interface{}{"event": map[string]interface{}{"end": map[string]interface{}{"error": eerr.Error()}}}, 0)
			send(map[string]string{}, connectEndStreamFlag)
			return
		}
		if res.Stdout != "" {
			send(stdoutEvent(res.Stdout), 0)
		}
		send(endEvent(res.ExitCode), 0)
	case os.Getenv("PVM_EXEC_SIM") == "1":
		out := fmt.Sprintf("simulated (%s): %s", task, command)
		send(stdoutEvent(out), 0)
		send(endEvent(0), 0)
	default:
		send(map[string]interface{}{"event": map[string]interface{}{"end": map[string]interface{}{"error": "no console session for task (boot a sandbox or set PVM_EXEC_SIM=1)"}}}, 0)
	}
	send(map[string]string{}, connectEndStreamFlag)
}

func envdProcessStdin(w http.ResponseWriter, r *http.Request, task string) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	payload := body
	if len(body) >= 5 {
		if _, p, err := envdReadEnvelope(strings.NewReader(string(body))); err == nil {
			payload = p
		}
	}
	var req struct {
		Data string `json:"data"`
	}
	_ = json.Unmarshal(payload, &req)
	sess, err := console.Default().Get(task)
	if err != nil {
		envdError(w, http.StatusNotFound, err.Error())
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		raw = []byte(req.Data) // tolerate literal input
	}
	if _, werr := sess.Stdin().Write(raw); werr != nil {
		envdError(w, http.StatusInternalServerError, werr.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func envdExecTimeout() time.Duration {
	if v := os.Getenv("PVM_EXEC_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 30 * time.Second
}

func stdoutEvent(s string) map[string]interface{} {
	return map[string]interface{}{"event": map[string]interface{}{"data": map[string]string{"stdout": base64.StdEncoding.EncodeToString([]byte(s))}}}
}

func endEvent(code int) map[string]interface{} {
	return map[string]interface{}{"event": map[string]interface{}{"end": map[string]interface{}{"exitCode": code}}}
}

// --- filesystem.Filesystem ---

func envdFilesystem(w http.ResponseWriter, r *http.Request) {
	method := strings.TrimPrefix(r.URL.Path, "/filesystem.Filesystem/")
	metricEnvdRequests.Inc("filesystem." + method)

	task, err := envdTaskID(r)
	if err != nil {
		envdError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws, err := taskWorkspace(task)
	if err != nil {
		envdError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var req map[string]string
	if r.Body != nil {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = json.Unmarshal(raw, &req)
	}
	if req == nil {
		req = map[string]string{}
	}

	switch method {
	case "ListDir":
		p, ferr := fenceJoin(ws, req["path"])
		if ferr != nil {
			envdError(w, http.StatusBadRequest, ferr.Error())
			return
		}
		entries, lerr := listDirEntries(p)
		if lerr != nil {
			envdError(w, http.StatusNotFound, lerr.Error())
			return
		}
		writeJSONBody(w, map[string]interface{}{"entries": entries})
	case "Stat":
		p, ferr := fenceJoin(ws, req["path"])
		if ferr != nil {
			envdError(w, http.StatusBadRequest, ferr.Error())
			return
		}
		entry, serr := statEntry(p)
		if serr != nil {
			envdError(w, http.StatusNotFound, serr.Error())
			return
		}
		writeJSONBody(w, map[string]interface{}{"entry": entry})
	case "MakeDir":
		p, ferr := fenceJoin(ws, req["path"])
		if ferr != nil {
			envdError(w, http.StatusBadRequest, ferr.Error())
			return
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			envdError(w, http.StatusInternalServerError, err.Error())
			return
		}
		entry, _ := statEntry(p)
		writeJSONBody(w, map[string]interface{}{"entry": entry})
	case "Remove":
		p, ferr := fenceJoin(ws, req["path"])
		if ferr != nil {
			envdError(w, http.StatusBadRequest, ferr.Error())
			return
		}
		if err := os.RemoveAll(p); err != nil {
			envdError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
	case "Move":
		from, ferr := fenceJoin(ws, req["source"])
		to, terr := fenceJoin(ws, req["destination"])
		if ferr != nil || terr != nil {
			envdError(w, http.StatusBadRequest, "bad source/destination")
			return
		}
		if err := os.Rename(from, to); err != nil {
			envdError(w, http.StatusInternalServerError, err.Error())
			return
		}
		entry, _ := statEntry(to)
		writeJSONBody(w, map[string]interface{}{"entry": entry})
	case "WatchDir":
		envdWatchDir(w, r, ws, req["path"])
	default:
		envdError(w, http.StatusNotImplemented, "filesystem.Filesystem/"+method+" not supported")
	}
}

type envdFileEntry struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // FILE | DIRECTORY
	Size    int64  `json:"size,omitempty"`
	ModTime string `json:"modTime,omitempty"`
}

func listDirEntries(dir string) ([]envdFileEntry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]envdFileEntry, 0, len(des))
	for _, de := range des {
		e := envdFileEntry{Name: de.Name(), Type: "FILE"}
		if de.IsDir() {
			e.Type = "DIRECTORY"
		} else if fi, err := de.Info(); err == nil {
			e.Size = fi.Size()
			e.ModTime = fi.ModTime().UTC().Format(time.RFC3339)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func statEntry(p string) (*envdFileEntry, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	e := &envdFileEntry{Name: filepath.Base(p), Type: "FILE", Size: fi.Size(), ModTime: fi.ModTime().UTC().Format(time.RFC3339)}
	if fi.IsDir() {
		e.Type = "DIRECTORY"
		e.Size = 0
	}
	return e, nil
}

// envdWatchDir streams directory change events (poll-based diff).
func envdWatchDir(w http.ResponseWriter, r *http.Request, ws, rel string) {
	p, ferr := fenceJoin(ws, rel)
	if ferr != nil {
		envdError(w, http.StatusBadRequest, ferr.Error())
		return
	}
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/connect+json")
	w.WriteHeader(http.StatusOK)

	snapshot := func() map[string]envdFileEntry {
		out := map[string]envdFileEntry{}
		if entries, err := listDirEntries(p); err == nil {
			for _, e := range entries {
				out[e.Name] = e
			}
		}
		return out
	}
	prev := snapshot()
	send := func(v any) {
		raw, _ := json.Marshal(v)
		w.Write(envdEncodeEnvelope(raw, 0))
		if flusher != nil {
			flusher.Flush()
		}
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			cur := snapshot()
			for name, e := range cur {
				if _, ok := prev[name]; !ok {
					send(map[string]interface{}{"event": map[string]interface{}{"name": name, "type": "CHANGED", "entry": e}})
				}
			}
			for name := range prev {
				if _, ok := cur[name]; !ok {
					send(map[string]interface{}{"event": map[string]interface{}{"name": name, "type": "REMOVED"}})
				}
			}
			prev = cur
		}
	}
}

// --- raw /files ---

func envdRawFiles(w http.ResponseWriter, r *http.Request) {
	metricEnvdRequests.Inc("files")
	task, err := envdTaskID(r)
	if err != nil {
		envdError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws, err := taskWorkspace(task)
	if err != nil {
		envdError(w, http.StatusInternalServerError, err.Error())
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		envdError(w, http.StatusBadRequest, "path required")
		return
	}
	p, ferr := fenceJoin(ws, path)
	if ferr != nil {
		envdError(w, http.StatusBadRequest, ferr.Error())
		return
	}
	switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, p)
	case http.MethodPost:
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			envdError(w, http.StatusInternalServerError, err.Error())
			return
		}
		dst, err := os.Create(p)
		if err != nil {
			envdError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if _, err := io.Copy(dst, io.LimitReader(r.Body, 256<<20)); err != nil {
			dst.Close()
			envdError(w, http.StatusInternalServerError, err.Error())
			return
		}
		dst.Close()
		w.WriteHeader(http.StatusOK)
	default:
		envdError(w, http.StatusMethodNotAllowed, "GET/POST only")
	}
}

// --- helpers ---

func envdError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": "envd_error", "message": msg})
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}
