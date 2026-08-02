package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
	"uml-container/internal/policy"
	"uml-container/internal/state"
)

// freePort returns a TCP port that is currently free, or skips the test.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot allocate a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// bootServer starts StartE2BServer on a free port and waits until it answers.
// If the embedded WebUI assets are missing (common in partial builds) or the
// port cannot be bound, the test is skipped rather than failed.
func bootServer(t *testing.T) string {
	t.Helper()
	state.RootDir = t.TempDir()
	port := freePort(t)

	ready := make(chan struct{})
	go func() {
		close(ready)
		if err := StartE2BServer(port); err != nil {
			t.Logf("StartE2BServer returned: %v", err)
		}
	}()
	<-ready

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	for i := 0; i < 40; i++ {
		resp, err := http.Get(base + "/api/containers")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return base
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Skip("StartE2BServer did not become ready (embedded WebUI assets missing?)")
	return ""
}

func TestServer_RejectsMissingAuth(t *testing.T) {
	base := bootServer(t)
	resp, err := http.Get(base + "/api/containers")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 401 or 400 without auth, got %d", resp.StatusCode)
	}
}

func TestServer_AcceptsBearerSecret(t *testing.T) {
	base := bootServer(t)
	req, _ := http.NewRequest(http.MethodGet, base+"/api/containers", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("valid bearer secret was rejected (401)")
	}
}

func TestServer_ExecRequiresTaskID(t *testing.T) {
	// /exec is now the Tool/Policy Gateway endpoint (plan.md §6). Without a
	// task id it must reject early (400), rather than silently executing.
	base := bootServer(t)
	req, _ := http.NewRequest(http.MethodPost, base+"/api/exec", strings.NewReader(`{"cmd":"ls"}`))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 (missing task id), got %d", resp.StatusCode)
	}
}

func TestServer_ExecNoGatewayReturns403(t *testing.T) {
	// A task id is supplied but no policy gateway registered for it: must be
	// 403 (default-deny), never executed.
	base := bootServer(t)
	req, _ := http.NewRequest(http.MethodPost, base+"/api/exec?task=ghost", strings.NewReader(`{"cmd":"ls"}`))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 (no gateway), got %d", resp.StatusCode)
	}
}

// TestServer_ExecHitsRegisteredGateway is the regression test for the split
// registry bug: before the fix, /api/exec read from a LOCAL registry that was
// never written to by RegisterPolicyGateway, so /api/exec ALWAYS returned 403
// even when a gateway was registered. Now both share globalRegistries, so a
// registered gateway must let /api/exec dispatch and return 200.
func TestServer_ExecHitsRegisteredGateway(t *testing.T) {
	base := bootServer(t)
	// Register a gateway that allows a read-only tool.
	gw := policy.NewGateway([]policy.Rule{
		{Name: "read_file", Action: policy.ActionAllow},
	}, nil)
	RegisterPolicyGateway("tk-exec", gw)
	t.Cleanup(func() { UnregisterPolicyGateway("tk-exec") })

	req, _ := http.NewRequest(http.MethodPost, base+"/api/exec?task=tk-exec", strings.NewReader(`{"cmd":"read_file"}`))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 with a registered gateway, got %d: %s", resp.StatusCode, body)
	}
}

func TestServer_RejectsInvalidContainerID(t *testing.T) {
	// Container IDs are validated by a ^[a-zA-Z0-9_-]+$ regex on the server.
	// We pass an obviously invalid id; the DELETE handler must 400 it, never
	// 200, so path-traversal cannot reach os.RemoveAll.
	base := bootServer(t)
	req, _ := http.NewRequest(http.MethodDelete, base+"/api/containers/bad!id", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid container id, got %d", resp.StatusCode)
	}
}

var _ = context.Background
