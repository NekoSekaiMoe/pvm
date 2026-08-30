package sdk

// envd.go — client for pvm's envd-compatible data plane (:49982 version
// websocket, :49983 Connect-JSON). The frame codec mirrors the envd
// protocol: every streaming message is [flags:1][len:4 BE][payload];
// flags bit 0x02 marks end-of-stream.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Connect envelope flags.
const (
	ConnectCompressedFlag = 0x01
	ConnectEndStreamFlag  = 0x02
)

// DefaultEnvdPort / DefaultEnvdWSPort are the E2B-conventional data ports.
const (
	DefaultEnvdPort   = 49983
	DefaultEnvdWSPort = 49982
)

// EncodeEnvelope frames one Connect message.
func EncodeEnvelope(payload []byte, flags byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flags
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// ReadEnvelope reads one frame; io.EOF on clean end.
func ReadEnvelope(r io.Reader) (flags byte, payload []byte, err error) {
	var head [5]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:5])
	if n > 32<<20 {
		return 0, nil, fmt.Errorf("envd: frame too large (%d)", n)
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return head[0], payload, nil
}

// maxRunOutputBytes bounds the combined stdout+stderr a single Run may
// accumulate; past it the stream is aborted instead of growing unbounded.
// (Each individual frame is additionally capped at 32 MiB by ReadEnvelope.)
const maxRunOutputBytes = 64 << 20 // 64 MiB

// EnvdClient speaks the Connect-JSON surface of one sandbox.
type EnvdClient struct {
	base string // http(s)://host:49983
	task string // X-Task-Id routing header
	http *http.Client
	user string
}

// NewEnvdClient builds a client for host (default 127.0.0.1). host may
// carry a port. Loopback hosts speak plain http (envd convention); anything
// else is addressed over https so credentials never cross in cleartext.
func NewEnvdClient(host string, task string) *EnvdClient {
	if host == "" {
		host = "127.0.0.1"
	}
	scheme := "https"
	if hostname := envdHostname(host); isLoopbackHost(hostname) {
		scheme = "http"
	}
	return &EnvdClient{
		base: scheme + "://" + host + ":" + fmt.Sprint(DefaultEnvdPort),
		task: task,
		http: &http.Client{Timeout: 120 * time.Second},
		user: "root",
	}
}

// envdHostname strips an optional port from a host[:port] string.
func envdHostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// CommandResult is one collected run.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type envdEvent struct {
	Event struct {
		Data struct {
			Stdout string `json:"stdout"`
			Stderr string `json:"stderr"`
		} `json:"data"`
		End *struct {
			ExitCode  *int   `json:"exitCode"`
			ExitCode2 *int   `json:"exit_code"`
			Status    string `json:"status"`
			Error     string `json:"error"`
			Exited    bool   `json:"exited"`
		} `json:"end"`
	} `json:"event"`
}

// Run executes a shell command via /process.Process/Start and collects the
// streamed stdout/stderr events until the end event.
func (e *EnvdClient) Run(ctx context.Context, command string, envs map[string]string) (*CommandResult, error) {
	proc := map[string]interface{}{
		"cmd":  "/bin/bash",
		"args": []string{"-l", "-c", command},
		"envs": envs,
	}
	payload, _ := json.Marshal(map[string]interface{}{"process": proc, "stdin": false})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/process.Process/Start", bytes.NewReader(EncodeEnvelope(payload, 0)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/connect+json")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Authorization", "Basic "+basicAuth(e.user))
	if e.task != "" {
		req.Header.Set("X-Task-Id", e.task)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("envd: Start -> %d: %s", resp.StatusCode, string(b))
	}

	br := bufio.NewReader(resp.Body)
	var out CommandResult
	for {
		flags, payload, rerr := ReadEnvelope(br)
		if rerr == io.EOF {
			return nil, fmt.Errorf("envd: stream ended without end event")
		}
		if rerr != nil {
			return nil, rerr
		}
		if flags&ConnectCompressedFlag != 0 {
			return nil, fmt.Errorf("envd: compressed frames unsupported")
		}
		if flags&ConnectEndStreamFlag != 0 {
			var trailer struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(payload, &trailer)
			if trailer.Error != "" {
				return nil, fmt.Errorf("envd: %s", trailer.Error)
			}
			return &out, nil
		}
		var ev envdEvent
		if err := json.Unmarshal(payload, &ev); err != nil {
			continue // tolerate unknown frames
		}
		if s := ev.Event.Data.Stdout; s != "" {
			out.Stdout += decodeB64(s)
		}
		if s := ev.Event.Data.Stderr; s != "" {
			out.Stderr += decodeB64(s)
		}
		if total := len(out.Stdout) + len(out.Stderr); total > maxRunOutputBytes {
			return nil, fmt.Errorf("envd: run output exceeded limit: %d bytes accumulated (stdout %d + stderr %d) > %d", total, len(out.Stdout), len(out.Stderr), maxRunOutputBytes)
		}
		if end := ev.Event.End; end != nil {
			switch {
			case end.ExitCode != nil:
				out.ExitCode = *end.ExitCode
			case end.ExitCode2 != nil:
				out.ExitCode = *end.ExitCode2
			case end.Status != "":
				out.ExitCode = exitCodeFromStatus(end.Status)
			case end.Error != "":
				return nil, fmt.Errorf("envd: process failed: %s", end.Error)
			case end.Exited:
				out.ExitCode = 0
			}
		}
	}
}

// Filesystem unary RPC helper (filesystem.Filesystem/<method>).
func (e *EnvdClient) fsRPC(ctx context.Context, method string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/filesystem.Filesystem/"+method, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Authorization", "Basic "+basicAuth(e.user))
	if e.task != "" {
		req.Header.Set("X-Task-Id", e.task)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("envd: %s -> %d: %s", method, resp.StatusCode, string(b))
	}
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// FileEntry is one filesystem list row.
type FileEntry struct {
	Name string `json:"name"`
	Type string `json:"type"` // file | directory
	Size int64  `json:"size"`
}

// FSList lists a directory.
func (e *EnvdClient) FSList(ctx context.Context, path string) ([]FileEntry, error) {
	var out struct {
		Entries []FileEntry `json:"entries"`
	}
	if err := e.fsRPC(ctx, "List", map[string]string{"path": path}, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

// FSMakeDirs creates a directory tree.
func (e *EnvdClient) FSMakeDirs(ctx context.Context, path string) error {
	return e.fsRPC(ctx, "Mkdir", map[string]string{"path": path}, nil)
}

// FSRemove removes a file/directory.
func (e *EnvdClient) FSRemove(ctx context.Context, path string) error {
	return e.fsRPC(ctx, "Remove", map[string]string{"path": path}, nil)
}

// FSRename renames/moves.
func (e *EnvdClient) FSRename(ctx context.Context, from, to string) error {
	return e.fsRPC(ctx, "Rename", map[string]string{"from": from, "to": to}, nil)
}

// RawFileURL builds the /files download URL.
func (e *EnvdClient) RawFileURL(path string) string {
	q := url.Values{"path": {path}, "username": {e.user}}
	return e.base + "/files?" + q.Encode()
}

// ReadFile downloads a file through the raw /files endpoint.
func (e *EnvdClient) ReadFile(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.RawFileURL(path), nil)
	if err != nil {
		return nil, err
	}
	if e.task != "" {
		req.Header.Set("X-Task-Id", e.task)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("envd: read %s -> %d", path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// WriteFile uploads a file through the raw /files endpoint.
func (e *EnvdClient) WriteFile(ctx context.Context, path string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.RawFileURL(path), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if e.task != "" {
		req.Header.Set("X-Task-Id", e.task)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("envd: write %s -> %d", path, resp.StatusCode)
	}
	return nil
}

func basicAuth(user string) string {
	return fmt.Sprintf("%s:%s", user, "") // "user:" — token omitted
}

func decodeB64(s string) string {
	// envd base64-encodes chunk payloads (stdout/stderr).
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s // not base64 — treat as literal (defensive)
	}
	return string(raw)
}

func exitCodeFromStatus(status string) int {
	switch status {
	case "exited", "exit_status":
		return 0
	case "signaled":
		return 128
	default:
		return -1
	}
}
