package api

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
