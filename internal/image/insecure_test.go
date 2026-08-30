package image

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"uml-container/internal/filesystem"
)

func TestInsecureEnabledMatrix(t *testing.T) {
	t.Setenv("PVM_REGISTRY_INSECURE", "")
	if insecureEnabled("http://reg.local:5000/img:1") != true {
		t.Fatal("explicit http:// must always enable insecure")
	}
	if insecureEnabled("reg.local:5000/img:1") != false {
		t.Fatal("without opt-in, plain ref must stay secure")
	}
	t.Setenv("PVM_REGISTRY_INSECURE", "1")
	if insecureEnabled("reg.local:5000/img:1") != true {
		t.Fatal("opt-in + private host must enable insecure")
	}
	if insecureEnabled("alpine:3") != false {
		t.Fatal("docker.io must NEVER go insecure via env")
	}
}

func TestRegistryHostPort(t *testing.T) {
	cases := map[string]string{
		"http://reg.local:5000/img:1": "reg.local:5000",
		"reg.local:5000/img:1":        "reg.local:5000",
		"alpine:3":                    "docker.io",
		"docker.io/library/alpine:3":  "docker.io",
	}
	for ref, want := range cases {
		if got := registryHostPort(ref); got != want {
			t.Fatalf("registryHostPort(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestSchemeRewriteForcesHTTP(t *testing.T) {
	srw := &schemeRewrite{host: "reg.local:5000", rt: fakeRT{}}
	req, _ := http.NewRequest(http.MethodGet, "https://reg.local:5000/v2/", nil)
	resp, err := srw.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-Seen-Scheme") != "http" {
		t.Fatal("rewriter must downgrade reg.local to http")
	}
	// Unrelated hosts pass through untouched.
	req2, _ := http.NewRequest(http.MethodGet, "https://example.com/v2/", nil)
	resp2, err := srw.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Header.Get("X-Seen-Scheme") != "https" {
		t.Fatal("unrelated hosts must keep https")
	}
}

type fakeRT struct{}

func (fakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	h := make(http.Header)
	h.Set("X-Seen-Scheme", req.URL.Scheme)
	return &http.Response{StatusCode: 200, Header: h, Body: http.NoBody}, nil
}

func TestSparseExt4ImageSavesSpace(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 unavailable; sparse assertion needs a real fs builder")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "sparse.img")
	const sizeMB = 300
	if err := filesystem.CreateExt4Image(p, sizeMB); err != nil {
		t.Skipf("mkfs failed (privileged env?): %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	// Apparent size must be the full 300MB, but allocated blocks must be
	// far smaller (mkfs metadata only) — that is the sparse win.
	if fi.Size() != int64(sizeMB)<<20 {
		t.Fatalf("apparent size = %d", fi.Size())
	}
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	du := st.Blocks * 512
	if du >= int64(sizeMB)<<20 {
		t.Fatalf("image consumed full %d bytes — not sparse", du)
	}
}
