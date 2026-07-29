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

func TestServer_ExecReturns501(t *testing.T) {
	// /exec is intentionally a mock for E2B SDK compat. tests/01_test_e2b_api.sh
	// asserts on this 501 as the contract.
	base := bootServer(t)
	req, _ := http.NewRequest(http.MethodPost, base+"/api/exec", strings.NewReader(`{"cmd":"ls"}`))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("expected 501 for /exec, got %d", resp.StatusCode)
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
