package image

// insecure.go — private HTTP registry support (bucket-5 #7): hosts listed on
// the allowlist (PVM_REGISTRY_ALLOWLIST) may be fetched over plain HTTP or
// unverified TLS when the operator opts in with PVM_REGISTRY_INSECURE=1 (or
// the ref carries an explicit http:// scheme). The allowlist stays the first
// gate: an insecure transport can never widen WHICH registries are reachable.

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"golang.org/x/sys/unix"
)

// cranePullOptions assembles crane options for a pull, arming the insecure
// transport only for allowlisted hosts.
func cranePullOptions(imageRef string) []crane.Option {
	if !insecureEnabled(imageRef) {
		return nil
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 — operator opt-in for named hosts
	rewrite := &schemeRewrite{host: registryHostPort(imageRef), rt: t}
	return []crane.Option{crane.WithTransport(rewrite)}
}

// insecureEnabled decides whether the ref may use the insecure transport:
// explicit http:// prefix wins; otherwise PVM_REGISTRY_INSECURE=1 applies to
// allowlisted non-default registries only (docker.io/https defaults stay
// pinned — an env typo must not silently disable TLS for the world).
func insecureEnabled(imageRef string) bool {
	if strings.HasPrefix(strings.ToLower(imageRef), "http://") {
		return true
	}
	if os.Getenv("PVM_REGISTRY_INSECURE") != "1" {
		return false
	}
	host := registryHostPort(imageRef)
	return host != "" && host != "docker.io" && host != "index.docker.io" && host != "registry-1.docker.io"
}

// registryHostPort applies the docker first-segment rule: the part before
// the first "/" is a registry only when it contains ".", ":" or equals
// "localhost"; otherwise the whole ref is a docker.io image name.
func registryHostPort(imageRef string) string {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(imageRef), "http://"), "https://")
	first := trimmed
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		first = trimmed[:i]
	} else {
		// No slash at all: the whole ref is a docker.io repository (the only
		// ":" in "alpine:3" is the tag separator, never a registry port).
		return "docker.io"
	}
	if first == "" || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		return "docker.io"
	}
	return first
}

// schemeRewrite forces plain HTTP for the configured host (the library
// would otherwise always attempt HTTPS and fail against http-only private
// registries).
type schemeRewrite struct {
	host string
	rt   http.RoundTripper
}

func (s *schemeRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && sameRegistryHost(req.URL.Host, s.host) {
		clone := req.Clone(req.Context())
		clone.URL.Scheme = "http"
		req = clone
	}
	return s.rt.RoundTrip(req)
}

// sameRegistryHost compares the request authority against the configured
// insecure registry EXACTLY (host and port). A HasPrefix check would also
// accept registry.example.evil — which merely shares a prefix — and ignore
// port mismatches, silently downgrading unrelated hosts to plaintext.
func sameRegistryHost(reqHost, configured string) bool {
	rh, rp := splitHostPort(reqHost)
	ch, cp := splitHostPort(configured)
	return strings.EqualFold(rh, ch) && rp == cp
}

func splitHostPort(hostport string) (string, string) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, ""
	}
	return h, p
}

// checkDiskHeadroom verifies free bytes on the filesystem holding dir are at
// least want×margin (PVM_IMAGE_SPACE_MARGIN, default 1.5), so a pull that
// cannot finish fails BEFORE it fills the disk other tenants share.
func checkDiskHeadroom(dir string, want int64) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return nil // cannot check (NFS quirks, permissions): do not block
	}
	margin := 1.5
	if v := os.Getenv("PVM_IMAGE_SPACE_MARGIN"); v != "" {
		var m float64
		if _, err := fmt.Sscanf(v, "%f", &m); err == nil && m >= 1 {
			margin = m
		}
	}
	free := int64(st.Bavail) * int64(st.Bsize)
	if free < int64(float64(want)*margin) {
		return fmt.Errorf("image: insufficient disk headroom in %s: free %d bytes < needed %d (x%.1f margin)",
			dir, free, want, margin)
	}
	return nil
}
