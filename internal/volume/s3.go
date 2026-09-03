package volume

// s3.go — the "s3" builtin volume driver: S3-compatible buckets mounted
// into the guest path through s3fs-fuse, the same operational model the
// reference deployment uses.
//
// Configuration (PluginConfig.Extra, all optional):
//
//	endpoint      http(s)://host[:port] (default: AWS S3)
//	bucket        bucket name (required at Attach — supplied as PrivateData
//	              by the Create hook convention "<bucket>/<prefix>")
//	region        region hint
//	path_style    "1" to force path-style addressing (MinIO et al.)
//
// Credentials come from the environment (AWS_ACCESS_KEY_ID /
// AWS_SECRET_ACCESS_KEY), NEVER from plugin config files in world-readable
// locations; a passwd file is materialized 0600 per attach and unlinked at
// detach. Attach mounts <base>/s3-<volumeID>; Detach (last ref) runs
// fusermount -u. Destroy scope stays with the Manager (prefix delete is
// the backend's concern).
//
// Requirements: s3fs + fuse on the host and CAP_SYS_ADMIN (or the
// user-allow_other fuse policy). Missing binaries fail the attach with a
// clear error instead of degrading silently.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// S3Plugin implements VolumePlugin over s3fs. It remembers each volume's
// mountpoint at Attach (the Detach wire form carries no base dir).
type S3Plugin struct {
	name string
	mu   sync.Mutex
	mnts map[string]string
}

// NewS3 returns the "s3" driver.
func NewS3(name string) *S3Plugin { return &S3Plugin{name: name, mnts: map[string]string{}} }

func (p *S3Plugin) Name() string           { return p.name }
func (p *S3Plugin) PluginType() PluginType { return PluginTypeBuiltin }

func (p *S3Plugin) Init(_ context.Context, cfg PluginConfig) error {
	p.name = cfg.Name
	return nil
}

// s3fsArgs builds the s3fs command line for one attach. Pure — tests
// assert the exact flags without touching fuse.
func s3fsArgs(mountpoint, bucket, endpoint, region string, pathStyle bool, passwdFile string) []string {
	args := []string{bucket, mountpoint,
		"-o", "passwd_file=" + passwdFile,
		"-o", "allow_other",
		"-o", "nosrvstat", // endpoint is authoritative; skip RPC autodetect
		"-o", "del_cache", // drop the local stat cache on unmount
		"-o", "umask=0002", // group-writable like the builtin dir driver
	}
	if endpoint != "" {
		args = append(args, "-o", "url="+endpoint)
	}
	if region != "" {
		args = append(args, "-o", "rdns=") // region via endpoint; keep reverse lookup off
		args = append(args, "-o", "connect_timeout=5")
	}
	if pathStyle {
		args = append(args, "-o", "use_path_request_style")
	}
	return args
}

// validateS3Endpoint refuses cleartext endpoints that would carry the
// AWS credential exchange (and object data) unencrypted: https by
// default; http only for loopback/localhost (local MinIO et al.) or
// behind the explicit PVM_S3_ALLOW_HTTP=1 private-network opt-in.
func validateS3Endpoint(endpoint string) error {
	if endpoint == "" {
		return nil // default AWS endpoints (https)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("volume s3: PVM_S3_ENDPOINT %q is not a valid endpoint URL", endpoint)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		if host == "localhost" {
			return nil
		}
		if os.Getenv("PVM_S3_ALLOW_HTTP") == "1" {
			return nil
		}
		return fmt.Errorf("volume s3: PVM_S3_ENDPOINT %q is cleartext http for a non-loopback host; use https or set PVM_S3_ALLOW_HTTP=1 explicitly", endpoint)
	default:
		return fmt.Errorf("volume s3: PVM_S3_ENDPOINT %q must be an http(s) URL", endpoint)
	}
}

func (p *S3Plugin) Attach(ctx context.Context, req *AttachRequest) (*AttachResult, error) {
	if req.VolumeBaseDir == "" {
		return nil, fmt.Errorf("volume s3: VolumeBaseDir required")
	}
	// The volume "name" carries the bucket (Create-hook convention
	// PrivateData = "<bucket>[/<prefix>]"; the Manager passes the raw id
	// through, so accept "s3-bucket" style ids as bucket names too).
	bucket := strings.TrimPrefix(req.VolumeID, p.name+"-")
	if req.PrivateData != "" {
		bucket = strings.SplitN(req.PrivateData, "/", 2)[0]
	}
	if bucket == "" {
		return nil, fmt.Errorf("volume s3: no bucket for volume %q (set private_data to <bucket>[/<prefix>])", req.VolumeID)
	}
	if _, err := exec.LookPath("s3fs"); err != nil {
		return nil, fmt.Errorf("volume s3: s3fs binary not found on PATH (install s3fs-fuse)")
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		return nil, fmt.Errorf("volume s3: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set")
	}
	// Endpoint scheme is validated BEFORE anything touches the disk: a
	// refused cleartext endpoint must not leave a .creds file (or a
	// mountpoint) behind.
	endpoint := os.Getenv("PVM_S3_ENDPOINT")
	if err := validateS3Endpoint(endpoint); err != nil {
		return nil, err
	}

	mountpoint := filepath.Join(req.VolumeBaseDir, fmt.Sprintf("%s-%s", p.name, req.VolumeID))
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return nil, fmt.Errorf("volume s3: mkdir %s: %w", mountpoint, err)
	}
	p.mu.Lock()
	p.mnts[req.VolumeID] = mountpoint
	p.mu.Unlock()
	// Already mounted (refcount > 1): reuse.
	if err := exec.Command("mountpoint", "-q", mountpoint).Run(); err == nil {
		return &AttachResult{VolumeID: req.VolumeID, HostPath: mountpoint,
			Metadata: map[string]string{"driver": p.name, "bucket": bucket, "reused": "1"}}, nil
	}

	pathStyle := strings.Contains(os.Getenv("PVM_S3_PATH_STYLE"), "1") || strings.Contains(endpoint, "minio") || strings.Contains(endpoint, "127.0.0.1")
	// Credentials file only AFTER the endpoint validated (and only when a
	// fresh mount is actually needed — the reuse path above never writes).
	passwd := filepath.Join(req.VolumeBaseDir, fmt.Sprintf(".%s-%s.creds", p.name, req.VolumeID))
	if err := os.WriteFile(passwd, []byte(fmt.Sprintf("%s:%s\n",
		os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))), 0o600); err != nil {
		return nil, fmt.Errorf("volume s3: credentials file: %w", err)
	}
	// s3fs reads passwd_file at startup and never re-reads it: unlink as
	// soon as the command returns (success OR failure) so the cleartext
	// key cannot linger past the mount (e.g. after a process crash —
	// Detach's own best-effort remove would never run then).
	defer os.Remove(passwd)
	args := s3fsArgs(mountpoint, bucket, endpoint, os.Getenv("PVM_S3_REGION"), pathStyle, passwd)
	cmd := exec.CommandContext(ctx, "s3fs", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("volume s3: s3fs mount %s: %v (%s)", bucket, err, strings.TrimSpace(string(out)))
	}
	return &AttachResult{
		VolumeID: req.VolumeID,
		HostPath: mountpoint,
		Metadata: map[string]string{"driver": p.name, "bucket": bucket, "hostPath": mountpoint},
	}, nil
}

func (p *S3Plugin) Detach(_ context.Context, req *DetachRequest) error {
	if !req.NodeRefLastDetach {
		return nil
	}
	p.mu.Lock()
	mountpoint := p.mnts[req.VolumeID]
	delete(p.mnts, req.VolumeID)
	p.mu.Unlock()
	if mountpoint == "" {
		return nil // never attached through this process: nothing to unmount
	}
	if out, err := exec.Command("fusermount", "-u", mountpoint).CombinedOutput(); err != nil {
		// Not mounted is success (idempotent detach).
		low := strings.ToLower(string(out))
		if !strings.Contains(low, "not mounted") && !strings.Contains(low, "no such file") && !strings.Contains(low, "not found") {
			return fmt.Errorf("volume s3: fusermount -u %s: %v (%s)", mountpoint, err, strings.TrimSpace(string(out)))
		}
	}
	_ = os.Remove(filepath.Join(filepath.Dir(mountpoint), fmt.Sprintf(".%s-%s.creds", p.name, req.VolumeID)))
	return nil
}

func (p *S3Plugin) Close() error { return nil }
