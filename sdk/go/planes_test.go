package sdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestEnvelopeRoundTrip(t *testing.T) {
	payload := []byte(`{"event":{"end":{"exitCode":3}}}`)
	frame := EncodeEnvelope(payload, 0)
	if len(frame) != 5+len(payload) {
		t.Fatalf("frame length = %d", len(frame))
	}
	flags, got, err := ReadEnvelope(bytes.NewReader(frame))
	if err != nil || flags != 0 || !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip failed: flags=%d err=%v", flags, err)
	}
	// EOS flag survives.
	eos := EncodeEnvelope([]byte(`{}`), ConnectEndStreamFlag)
	flags, _, err = ReadEnvelope(bytes.NewReader(eos))
	if err != nil || flags != ConnectEndStreamFlag {
		t.Fatalf("eos flags = %d err=%v", flags, err)
	}
}

func TestSandboxLifecycle(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Header.Get("X-API-KEY") != "k" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/sandboxes":
			_ = json.NewEncoder(w).Encode([]SandboxInfo{{SandboxID: "sb-1", Template: "tpl-a"}})
		case r.Method == "POST" && r.URL.Path == "/sandboxes":
			if r.URL.Query().Get("template") != "tpl-a" || r.URL.Query().Get("timeout") != "-1" {
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(SandboxInfo{SandboxID: "sb-2"})
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case r.Method == "POST" && r.URL.Path == "/sandboxes/sb-1/refreshes":
			var body map[string]int
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["duration"] != 600 {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	c, err := NewClient(Config{APIURL: ts.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}

	list, err := c.ListSandboxes(context.Background())
	if err != nil || len(list) != 1 || list[0].SandboxID != "sb-1" {
		t.Fatalf("list: %v %+v", err, list)
	}
	sb, err := c.CreateSandbox(context.Background(), CreateSandboxOptions{Template: "tpl-a", TimeoutSeconds: NeverTimeout})
	if err != nil || sb.SandboxID != "sb-2" {
		t.Fatalf("create: %v %+v", err, sb)
	}
	if err := c.RefreshSandbox(context.Background(), "sb-1", 600); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := c.KillSandbox(context.Background(), "sb-1"); err != nil {
		t.Fatalf("kill: %v", err)
	}
	// Missing template+alias is a client-side error, no request.
	if _, err := c.CreateSandbox(context.Background(), CreateSandboxOptions{}); err == nil {
		t.Fatal("create without template must fail client-side")
	}
}

func TestExecApprovalSentinel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/exec" || r.URL.Query().Get("task") != "t-9" {
			w.WriteHeader(404)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["cmd"] == "deploy env=prod" {
			w.WriteHeader(202)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "approval_required", "ticket": "tkt-1"})
			return
		}
		_ = json.NewEncoder(w).Encode(ExecResult{OK: true, Summary: "ran"})
	}))
	defer ts.Close()
	c, err := NewClient(Config{APIURL: ts.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}

	res, err := c.Exec(context.Background(), "t-9", "deploy env=prod")
	if err == nil || res != nil {
		t.Fatalf("expected sentinel, got res=%+v err=%v", res, err)
	}
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("must be ErrApprovalRequired, got %v", err)
	}
	res, err = c.Exec(context.Background(), "t-9", "read x=1")
	if err != nil || !res.OK {
		t.Fatalf("plain exec: %v %+v", err, res)
	}
}

func TestEnvdRunCollectsStream(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/process.Process/Start" {
			w.WriteHeader(404)
			return
		}
		frames := [][]byte{
			EncodeEnvelope(mustJSON(t, map[string]interface{}{
				"event": map[string]interface{}{"data": map[string]string{"stdout": b64("hello ")}},
			}), 0),
			EncodeEnvelope(mustJSON(t, map[string]interface{}{
				"event": map[string]interface{}{"data": map[string]string{"stdout": b64("world")}},
			}), 0),
			EncodeEnvelope(mustJSON(t, map[string]interface{}{
				"event": map[string]interface{}{"end": map[string]interface{}{"exitCode": 7}},
			}), 0),
			EncodeEnvelope([]byte(`{}`), ConnectEndStreamFlag),
		}
		for _, f := range frames {
			w.Write(f)
		}
	}))
	defer ts.Close()

	e := NewEnvdClient("", "t-9")
	e.base = ts.URL
	res, err := e.Run(context.Background(), "true", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "hello world" || res.ExitCode != 7 {
		t.Fatalf("bad result: %+v", res)
	}
}

func TestEnvdFilesystem(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/filesystem.Filesystem/List":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entries": []FileEntry{{Name: "a.txt", Type: "file", Size: 3}},
			})
		case r.URL.Path == "/files":
			_, _ = w.Write([]byte("file-body"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	e := NewEnvdClient("", "")
	e.base = ts.URL

	entries, err := e.FSList(context.Background(), "/")
	if err != nil || len(entries) != 1 || entries[0].Name != "a.txt" {
		t.Fatalf("list: %v %+v", err, entries)
	}
	body, err := e.ReadFile(context.Background(), "/a.txt")
	if err != nil || string(body) != "file-body" {
		t.Fatalf("read: %v %q", err, body)
	}
}
