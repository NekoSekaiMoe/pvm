package volume

// rpc_test.go — the Unix-socket NDJSON plugin protocol against a fake
// plugin server, plus the s3fs argv construction.

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRPCPlugin serves the wire protocol from a table of responses.
func fakeRPCPlugin(t *testing.T, handler func(req map[string]interface{}) map[string]interface{}) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "plugin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadBytes('\n')
				if err != nil {
					return
				}
				var req map[string]interface{}
				if json.Unmarshal(line, &req) != nil {
					return
				}
				resp, _ := json.Marshal(handler(req))
				c.Write(append(resp, '\n'))
			}(conn)
		}
	}()
	return sock
}

func TestRPCPluginAttachDetach(t *testing.T) {
	var seenOps []string
	sock := fakeRPCPlugin(t, func(req map[string]interface{}) map[string]interface{} {
		seenOps = append(seenOps, req["op"].(string))
		switch req["op"] {
		case "attach":
			if req["volume_id"] != "vol9" || req["node_ref_first_attach"] != true {
				t.Errorf("attach wire fields wrong: %v", req)
			}
			return map[string]interface{}{
				"volume_id": "vol9",
				"host_path": "/data/rpc1-vol9",
				"metadata":  map[string]string{"kind": "fake"},
			}
		default:
			return map[string]interface{}{}
		}
	})

	p := NewRPC("rpc1", sock)
	if err := p.Init(context.Background(), PluginConfig{Name: "rpc1", Type: PluginTypeRPC, SocketPath: sock}); err != nil {
		t.Fatal(err)
	}
	res, err := p.Attach(context.Background(), &AttachRequest{
		SandboxID: "s", VolumeID: "vol9", Driver: "rpc1",
		RefCount: 0, NodeRefFirstAttach: true, VolumeBaseDir: "/data",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.HostPath != "/data/rpc1-vol9" || res.Metadata["kind"] != "fake" {
		t.Fatalf("attach result = %+v", res)
	}
	if err := p.Detach(context.Background(), &DetachRequest{SandboxID: "s", VolumeID: "vol9", NodeRefLastDetach: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seenOps, ",") != "attach,detach" {
		t.Fatalf("ops = %v", seenOps)
	}
}

func TestRPCPluginErrorPropagation(t *testing.T) {
	sock := fakeRPCPlugin(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"error": "bucket_missing", "error_data": "no such bucket"}
	})
	p := NewRPC("rpc1", sock)
	_, err := p.Attach(context.Background(), &AttachRequest{VolumeID: "v", Driver: "rpc1"})
	if err == nil || !strings.Contains(err.Error(), "bucket_missing") {
		t.Fatalf("plugin error must propagate: %v", err)
	}
}

func TestRPCPluginUnreachableSocket(t *testing.T) {
	p := NewRPC("rpc1", "/nonexistent/plugin.sock")
	if _, err := p.Attach(context.Background(), &AttachRequest{VolumeID: "v"}); err == nil {
		t.Fatal("unreachable socket must fail the hook")
	}
}

func TestRPCPluginManagerIntegration(t *testing.T) {
	// The full Manager path: register + attach (validation + result checks
	// included). A lying host_path outside the base dir must be rejected by
	// the Manager's containment rule.
	sock := fakeRPCPlugin(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"volume_id": "volx", "host_path": "/elsewhere"}
	})
	base := t.TempDir()
	m := NewManager(base)
	if err := m.Register(context.Background(), PluginConfig{Name: "rpc1", Type: PluginTypeRPC, SocketPath: sock}, NewRPC("rpc1", sock)); err != nil {
		t.Fatal(err)
	}
	_, err := m.Attach(context.Background(), &AttachRequest{SandboxID: "s", VolumeID: "volx", Driver: "rpc1"})
	if err == nil || !strings.Contains(err.Error(), "VolumeBaseDir") {
		t.Fatalf("escaping host path must be rejected, got %v", err)
	}
}

func TestS3FSArgv(t *testing.T) {
	args := s3fsArgs("/mnt/x", "mybucket", "http://127.0.0.1:9000", "us-east-1", true, "/tmp/creds")
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"mybucket /mnt/x",
		"passwd_file=/tmp/creds",
		"url=http://127.0.0.1:9000",
		"use_path_request_style",
		"allow_other",
	} {
		t.Run("has "+want, func(t *testing.T) {
			if !strings.Contains(joined, want) {
				t.Fatalf("s3fs argv missing %q: %s", want, joined)
			}
		})
	}
	// Path style off by default for real S3 endpoints.
	t.Run("path style off for real S3 endpoints", func(t *testing.T) {
		args = s3fsArgs("/mnt/x", "b", "", "", false, "/tmp/c")
		if strings.Contains(strings.Join(args, " "), "use_path_request_style") {
			t.Fatal("path style must be opt-in")
		}
	})
}

func TestS3PluginMissingBinaryFailsClosed(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "k")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "s")
	t.Setenv("PATH", t.TempDir()) // no s3fs anywhere
	p := NewS3("s3")
	// Fake the binary presence check outcome by pointing at a bucket via
	// PrivateData; with an empty PATH LookPath fails first.
	_, err := p.Attach(context.Background(), &AttachRequest{
		VolumeID: "v", Driver: "s3", VolumeBaseDir: t.TempDir(), PrivateData: "bucket/prefix",
	})
	if err == nil || !strings.Contains(err.Error(), "s3fs binary not found") {
		t.Fatalf("missing s3fs must fail closed, got %v", err)
	}
	_ = os.Getenv("PATH")
}

// Production attach path must refuse cleartext S3 endpoints that are not
// loopback (credentials would ride the wire unencrypted); https and
// loopback http stay allowed, and PVM_S3_ALLOW_HTTP=1 is the explicit
// private-network opt-in.
func TestValidateS3Endpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		optin    string
		wantErr  bool
	}{
		{"empty defaults to https AWS", "", "", false},
		{"https allowed", "https://s3.example", "", false},
		{"loopback http allowed", "http://127.0.0.1:9000", "", false},
		{"localhost http allowed", "http://localhost:9000", "", false},
		{"remote http refused", "http://s3.example", "", true},
		{"remote http refused with junk optin", "http://s3.example", "yes", true},
		{"remote http explicit opt-in", "http://s3.example", "1", false},
		{"garbage refused", "not a url :", "", true},
		{"wrong scheme refused", "ftp://s3.example", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PVM_S3_ALLOW_HTTP", tc.optin)
			err := validateS3Endpoint(tc.endpoint)
			if tc.wantErr && err == nil {
				t.Fatalf("validateS3Endpoint(%q) must fail", tc.endpoint)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateS3Endpoint(%q) = %v, want ok", tc.endpoint, err)
			}
		})
	}
}
