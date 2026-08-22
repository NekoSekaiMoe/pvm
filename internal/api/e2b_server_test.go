package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"uml-container/internal/lifecycle"
	"uml-container/internal/policy"
	"uml-container/internal/state"
	"uml-container/internal/template"
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
	// The server refuses to start without a secret (no default credential);
	// tests authenticate with this one.
	t.Setenv("API_SECRET", "secret")
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

// TestRearmAllAutopause covers the server-restart restore: tasks persisted
// as RUNNING with a valid idle_timeout must get their autopause timer back
// (observable by the task actually suspending), while suspended tasks,
// running tasks without a timeout, and unparseable timeouts stay untouched.
func TestRearmAllAutopause(t *testing.T) {
	origRoot := state.RootDir
	state.RootDir = t.TempDir()
	t.Cleanup(func() { state.RootDir = origRoot })
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())

	save := func(id string, status state.Status, idle string) {
		t.Helper()
		st := &state.ContainerState{ID: id, Name: id, Status: status, IdleTimeout: idle}
		if err := state.SaveState(id, st); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	save("run-timeout", state.StatusRunning, "10ms")              // must arm
	save("run-notimeout", state.StatusRunning, "")                // nothing to arm
	save("run-badtimeout", state.StatusRunning, "not-a-duration") // skipped
	save("suspended", state.StatusSuspended, "10ms")              // not Running

	rearmAllAutopause(lifecycle.New(nil))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st, err := state.LoadState("run-timeout")
		if err == nil && st.Status == state.StatusSuspended {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if st, _ := state.LoadState("run-timeout"); st == nil || st.Status != state.StatusSuspended {
		t.Fatalf("running task with idle_timeout was not re-armed: %+v", st)
	}
	// Tasks that must NOT be touched by the restart re-arm, as table-driven
	// subtests: each keeps the status it was persisted with (the suspended
	// one in particular must not be resumed by the re-arm pass).
	untouched := []struct {
		id   string
		want state.Status
	}{
		{"run-notimeout", state.StatusRunning},
		{"run-badtimeout", state.StatusRunning},
		{"suspended", state.StatusSuspended},
	}
	for _, tc := range untouched {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			st, err := state.LoadState(tc.id)
			if err != nil {
				t.Fatalf("load %s: %v", tc.id, err)
			}
			if st.Status != tc.want {
				t.Fatalf("%s: status = %q, want %q (must stay untouched by re-arm)", tc.id, st.Status, tc.want)
			}
		})
	}
}

// seedLifecycleTask saves a task with explicit lifecycle config so tests can
// pin the auto_resume / idle_timeout behavior of the endpoints.
func seedLifecycleTask(t *testing.T, id string, status state.Status, idle string, autoResume bool) {
	t.Helper()
	st := &state.ContainerState{ID: id, Name: id, Status: status, IdleTimeout: idle, AutoResume: autoResume}
	if err := state.SaveState(id, st); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// TestServer_ResumeNotGatedOnAutoResume is the regression test for the
// explicit resume endpoint: an operator's POST /tasks/:id/resume must always
// resume a Suspended task. The auto_resume flag only governs the AUTOMATIC
// resume path (lifecycleActivity on /exec activity), so with AutoResume=false
// the old handler wrongly answered 409.
func TestServer_ResumeNotGatedOnAutoResume(t *testing.T) {
	// Point the server's cgroup manager at a temp root: Thaw then fails
	// with ENOENT, which Manager.Resume tolerates (task never had a cgroup).
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())
	base := bootServer(t)

	seedLifecycleTask(t, "tk-resume", state.StatusSuspended, "", false)
	resp, out := doJSON(t, "POST", base, "/api/tasks/tk-resume/resume", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("explicit resume with auto_resume=false: status=%d body=%v", resp.StatusCode, out)
	}
	if st, _ := state.LoadState("tk-resume"); st == nil || st.Status != state.StatusRunning {
		t.Fatalf("task must be Running after explicit resume, got %+v", st)
	}
}

// TestAPI_Transition_DoesNotAutoResumeSuspended pins the /transition
// behavior: API activity on the transition endpoint only bumps a RUNNING
// task's idle timer — a Suspended task goes through the plain FSM validation.
// An invalid edge (suspended -> running) must be a 409 with the task left
// Suspended, NOT an implicit resume that turns the request into a success;
// a VALID edge (suspended -> quarantined) still applies as requested.
func TestAPI_Transition_DoesNotAutoResumeSuspended(t *testing.T) {
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())
	base := bootServer(t)

	seedLifecycleTask(t, "tk-tr-susp", state.StatusSuspended, "", true)
	resp, out := doJSON(t, "POST", base, "/api/tasks/tk-tr-susp/transition",
		map[string]string{"to": "running", "actor": "controller"})
	if resp.StatusCode != 409 {
		t.Fatalf("implicit resume via /transition must be rejected, got %d body=%v", resp.StatusCode, out)
	}
	if st, _ := state.LoadState("tk-tr-susp"); st == nil || st.Status != state.StatusSuspended {
		t.Fatalf("suspended task must stay suspended after rejected transition, got %+v", st)
	}

	// A valid explicit edge from Suspended still works (no resume involved).
	resp, out = doJSON(t, "POST", base, "/api/tasks/tk-tr-susp/transition",
		map[string]string{"to": "quarantined", "actor": "controller", "reason": "incident"})
	if resp.StatusCode != 200 {
		t.Fatalf("valid transition from suspended: status=%d body=%v", resp.StatusCode, out)
	}
	if st, _ := state.LoadState("tk-tr-susp"); st == nil || st.Status != state.StatusQuarantined {
		t.Fatalf("task must be quarantined after valid transition, got %+v", st)
	}
}

// TestServer_ExecAutoResumeStillWorks protects the /exec activity path after
// the /transition change: API activity on /exec still honors auto_resume —
// a Suspended task with AutoResume=true is resumed by the request and the
// gateway call proceeds; with AutoResume=false the task stays Suspended
// (but the gateway still serves the call).
func TestServer_ExecAutoResumeStillWorks(t *testing.T) {
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())
	base := bootServer(t)

	gw := policy.NewGateway([]policy.Rule{
		{Name: "read_file", Action: policy.ActionAllow},
	}, nil)
	RegisterPolicyGateway("tk-exec-resume", gw)
	RegisterPolicyGateway("tk-exec-norsm", gw)
	t.Cleanup(func() {
		UnregisterPolicyGateway("tk-exec-resume")
		UnregisterPolicyGateway("tk-exec-norsm")
	})

	seedLifecycleTask(t, "tk-exec-resume", state.StatusSuspended, "", true)
	resp, out := doJSON(t, "POST", base, "/api/exec?task=tk-exec-resume", map[string]string{"cmd": "read_file"})
	if resp.StatusCode != 200 {
		t.Fatalf("exec on auto-resumable task: status=%d body=%v", resp.StatusCode, out)
	}
	if st, _ := state.LoadState("tk-exec-resume"); st == nil || st.Status != state.StatusRunning {
		t.Fatalf("suspended task with auto_resume=true must be resumed by activity, got %+v", st)
	}

	seedLifecycleTask(t, "tk-exec-norsm", state.StatusSuspended, "", false)
	resp, out = doJSON(t, "POST", base, "/api/exec?task=tk-exec-norsm", map[string]string{"cmd": "read_file"})
	if resp.StatusCode != 200 {
		t.Fatalf("exec must still run for a suspended task (no auto-resume): status=%d body=%v", resp.StatusCode, out)
	}
	if st, _ := state.LoadState("tk-exec-norsm"); st == nil || st.Status != state.StatusSuspended {
		t.Fatalf("suspended task with auto_resume=false must stay suspended, got %+v", st)
	}
}

// TestAPI_TemplateCreate_IsPending pins the template lifecycle at creation:
// POST /templates registers a PENDING record (READY — and with it alias
// eligibility — is reached only after the image build completes), and an
// alias supplied at creation is rejected per the store's READY-only rule.
func TestAPI_TemplateCreate_IsPending(t *testing.T) {
	t.Setenv("PVM_TEMPLATE_ROOT", t.TempDir())
	base := bootServer(t)

	resp, out := doJSON(t, "POST", base, "/api/templates", map[string]string{"image_ref": "alpine:3"})
	if resp.StatusCode != 201 {
		t.Fatalf("create template: status=%d body=%v", resp.StatusCode, out)
	}
	if out["status"] != "PENDING" {
		t.Fatalf("created template status = %v, want PENDING", out["status"])
	}

	// The store enforces aliases-on-READY: claiming an alias at creation of
	// a (still PENDING) template must be a 400, not a silent success.
	resp, out = doJSON(t, "POST", base, "/api/templates", map[string]string{"image_ref": "alpine:3", "alias": "nope"})
	if resp.StatusCode != 400 {
		t.Fatalf("alias at creation must be rejected for PENDING template, got %d body=%v", resp.StatusCode, out)
	}
}

// TestAPI_TemplateAliasAndDeleteByAlias covers identifier resolution on the
// mutating template endpoints: SetAlias and DELETE accept BOTH raw template
// ids and aliases in the path, mirroring GET /templates/:id.
func TestAPI_TemplateAliasAndDeleteByAlias(t *testing.T) {
	tplRoot := t.TempDir()
	t.Setenv("PVM_TEMPLATE_ROOT", tplRoot)
	base := bootServer(t)

	// Seed a READY template directly in the store root: SetAlias requires
	// READY, while POST /templates (correctly) creates PENDING records.
	seedStore := template.NewStore(tplRoot)
	readyID := template.GenerateTemplateID()
	if err := seedStore.Create(template.Record{TemplateID: readyID, ImageRef: "alpine", Status: "READY", Kind: "template"}); err != nil {
		t.Fatalf("seed READY template: %v", err)
	}

	// Claim an alias by raw id.
	resp, out := doJSON(t, "POST", base, "/api/templates/"+readyID+"/alias", map[string]string{"alias": "mytpl"})
	if resp.StatusCode != 200 {
		t.Fatalf("SetAlias by id: status=%d body=%v", resp.StatusCode, out)
	}
	if out["alias"] != "mytpl" {
		t.Fatalf("alias after set = %v, want mytpl", out["alias"])
	}

	// Re-set the alias addressing the template BY its current alias.
	resp, out = doJSON(t, "POST", base, "/api/templates/mytpl/alias", map[string]string{"alias": "mytpl2"})
	if resp.StatusCode != 200 {
		t.Fatalf("SetAlias by alias: status=%d body=%v", resp.StatusCode, out)
	}
	if out["alias"] != "mytpl2" {
		t.Fatalf("alias after re-set = %v, want mytpl2", out["alias"])
	}

	// DELETE addressing the template by its alias.
	resp, _ = doJSON(t, "DELETE", base, "/api/templates/mytpl2", nil)
	if resp.StatusCode != 204 {
		t.Fatalf("DELETE by alias: status=%d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "GET", base, "/api/templates/"+readyID, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("template must be gone after delete, got %d", resp.StatusCode)
	}
}

func TestValidateAPIRootfs_ResolvesSymlinksAndKeepsFormatChecks(t *testing.T) {
	root := t.TempDir()
	// The image root itself is reached through a symlink (e.g. /var/lib on a
	// symlinked mount): BOTH sides must be resolved before containment.
	realDir := filepath.Join(root, "images-real")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatalf("mkdir image dir: %v", err)
	}
	aliasDir := filepath.Join(root, "images-alias")
	if err := os.Symlink(realDir, aliasDir); err != nil {
		t.Fatalf("symlink image dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "alpine.img"), []byte("x"), 0644); err != nil {
		t.Fatalf("seed image: %v", err)
	}

	// Input-format and absolute-path checks fire BEFORE any resolution and
	// keep their messages.
	for _, tc := range []struct{ name, in, want string }{
		{"empty_rootfs", "", "rootfs is required"},
		{"space_in_path", "/a b", "whitespace"},
		{"colon_in_path", "/a:b", "whitespace"},
		{"relative_path", "relative/path", "absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateRootfsUnder(tc.in, aliasDir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rootfs %q: want error containing %q, got %v", tc.in, tc.want, err)
			}
		})
	}

	// A rootfs reached through the symlinked image root resolves to the real
	// trusted path, which is what the caller must keep using.
	got, err := validateRootfsUnder(filepath.Join(aliasDir, "alpine.img"), aliasDir)
	if err != nil {
		t.Fatalf("valid rootfs through symlinked image dir: %v", err)
	}
	if want := filepath.Join(realDir, "alpine.img"); got != want {
		t.Fatalf("resolved rootfs = %q, want the trusted resolved path %q", got, want)
	}

	// A symlinked final component inside the image root resolves to its
	// in-root target.
	if err := os.Symlink("alpine.img", filepath.Join(realDir, "current.img")); err != nil {
		t.Fatalf("symlink image: %v", err)
	}
	got, err = validateRootfsUnder(filepath.Join(aliasDir, "current.img"), aliasDir)
	if err != nil {
		t.Fatalf("symlinked final component: %v", err)
	}
	if want := filepath.Join(realDir, "alpine.img"); got != want {
		t.Fatalf("resolved symlinked rootfs = %q, want %q", got, want)
	}

	// Symlink swap: the raw path sits under the image root, but resolves
	// outside it — must be rejected by the post-resolution containment check
	// (the swapped-to file must EXIST so resolution succeeds and the escape
	// is caught by containment, not by a resolve error).
	elsewhere := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0755); err != nil {
		t.Fatalf("mkdir elsewhere: %v", err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "evil.img"), []byte("x"), 0644); err != nil {
		t.Fatalf("seed evil image: %v", err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(realDir, "swapped")); err != nil {
		t.Fatalf("symlink swap: %v", err)
	}
	if _, err := validateRootfsUnder(filepath.Join(aliasDir, "swapped", "evil.img"), aliasDir); err == nil ||
		!strings.Contains(err.Error(), "rootfs must live under") {
		t.Fatalf("symlink-swapped rootfs must be rejected post-resolution, got %v", err)
	}
}
