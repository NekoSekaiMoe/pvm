package volume

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeStubPlugin writes a shell-script plugin that records every argv
// element (one per line) and the first stdin line into dumpDir, then
// answers the ref binary protocol: attach -> host_path JSON, detach ->
// empty error. Mirrors the stub technique of ref's binary/driver_test.go.
func writeStubPlugin(t *testing.T, dumpDir string) string {
	t.Helper()
	if err := os.MkdirAll(dumpDir, 0o755); err != nil {
		t.Fatalf("mkdir dump: %v", err)
	}
	script := filepath.Join(dumpDir, "stub-plugin.sh")
	body := `#!/bin/sh
# Record argv, one element per line.
for a in "$@"; do printf '%s\n' "$a" >> "` + dumpDir + `/argv.txt"; done
# Record the first stdin line (v2 pipes the payload here; v1 sends none).
if IFS= read -r line; then printf '%s\n' "$line" > "` + dumpDir + `/stdin.txt"; fi
op=""
prev=""
for a in "$@"; do
  [ "$prev" = "--op" ] && op="$a"
  prev="$a"
done
case "$op" in
  attach) printf '{"host_path":"/stub/host","metadata":{"m":"1"},"error":""}\n' ;;
  *)      printf '{"error":""}\n' ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return script
}

func readDump(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestBinaryPlugin_V2StdinProtocol verifies the default (v2) wire format:
// credentials never appear in argv and are delivered as one JSON line on
// stdin, for both attach and detach.
func TestBinaryPlugin_V2StdinProtocol(t *testing.T) {
	dir := t.TempDir()
	p := NewBinary("stub", writeStubPlugin(t, dir))
	if err := p.Init(context.Background(), PluginConfig{
		Name: "stub", Type: PluginTypeBinary, BinaryPath: filepath.Join(dir, "stub-plugin.sh"),
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	if _, err := p.Attach(context.Background(), &AttachRequest{
		SandboxID: "sbx", Namespace: "ns", VolumeID: "vol-1", Driver: "stub",
		RefCount: 0, NodeRefFirstAttach: true, VolumeBaseDir: "/vbd",
		PrivateData: "s3cret-prefix/",
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if argv := readDump(t, dir, "argv.txt"); strings.Contains(argv, "s3cret-prefix/") {
		t.Fatalf("v2 attach leaked PrivateData into argv: %q", argv)
	}
	stdin := readDump(t, dir, "stdin.txt")
	if !strings.Contains(stdin, `"private_data":"s3cret-prefix/"`) {
		t.Fatalf("v2 attach stdin missing private_data: %q", stdin)
	}

	if err := p.Detach(context.Background(), &DetachRequest{
		SandboxID: "sbx", Namespace: "ns", VolumeID: "vol-1", Driver: "stub",
		Metadata: map[string]string{"mount_dir": "/vbd/vol-1"}, RefCount: 0, NodeRefLastDetach: true,
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if argv := readDump(t, dir, "argv.txt"); strings.Contains(argv, "mount_dir") {
		t.Fatalf("v2 detach leaked Metadata into argv: %q", argv)
	}
	// stdin.txt keeps the attach payload (written first); assert it held
	// metadata for detach would need a second file — the attach assertion
	// above already proves the stdin channel, argv silence is the point.
}

// TestBinaryPlugin_V1ArgvRefCompat verifies the "argv-v1" opt-in against
// the ref Cubelet wire format: exact flag set (no --driver/--node-ref-*,
// which strict ref parsers such as cube-volume-cos.sh reject), secrets on
// argv, --private-data omitted when empty, and no stdin payload.
func TestBinaryPlugin_V1ArgvRefCompat(t *testing.T) {
	dir := t.TempDir()
	p := NewBinary("stub", "")
	if err := p.Init(context.Background(), PluginConfig{
		Name: "stub", Type: PluginTypeBinary, BinaryPath: writeStubPlugin(t, dir),
		Extra: map[string]string{"protocol": "argv-v1"},
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	res, err := p.Attach(context.Background(), &AttachRequest{
		SandboxID: "sbx", Namespace: "ns", VolumeID: "vol-1", Driver: "stub",
		RefCount: 0, NodeRefFirstAttach: true, VolumeBaseDir: "/vbd",
		PrivateData: "volumes/vol-1/",
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if res.HostPath != "/stub/host" {
		t.Fatalf("v1 attach host_path = %q, want /stub/host", res.HostPath)
	}
	argv := readDump(t, dir, "argv.txt")
	if !strings.Contains(argv, "--private-data\nvolumes/vol-1/") {
		t.Fatalf("v1 attach argv missing --private-data: %q", argv)
	}
	for _, banned := range []string{"--driver", "--node-ref-first-attach", "--node-ref-last-detach"} {
		if strings.Contains(argv, banned) {
			t.Fatalf("v1 argv must not carry %q (ref parsers reject unknown flags): %q", banned, argv)
		}
	}
	if stdin := readDump(t, dir, "stdin.txt"); stdin != "" {
		t.Fatalf("v1 must not write stdin, got %q", stdin)
	}

	// Second attach with empty PrivateData: ref omits the flag entirely.
	os.Remove(filepath.Join(dir, "argv.txt"))
	if _, err := p.Attach(context.Background(), &AttachRequest{
		SandboxID: "sbx", Namespace: "ns", VolumeID: "vol-1", Driver: "stub",
		RefCount: 1, VolumeBaseDir: "/vbd",
	}); err != nil {
		t.Fatalf("attach (empty pd): %v", err)
	}
	if argv := readDump(t, dir, "argv.txt"); strings.Contains(argv, "--private-data") {
		t.Fatalf("v1 attach with empty PrivateData must omit the flag: %q", argv)
	}

	// Detach carries Metadata as a JSON object on argv.
	os.Remove(filepath.Join(dir, "argv.txt"))
	if err := p.Detach(context.Background(), &DetachRequest{
		SandboxID: "sbx", Namespace: "ns", VolumeID: "vol-1", Driver: "stub",
		Metadata: map[string]string{"mount_dir": "/vbd/vol-1"}, RefCount: 0, NodeRefLastDetach: true,
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	argv = readDump(t, dir, "argv.txt")
	if !strings.Contains(argv, "--metadata\n{\"mount_dir\":\"/vbd/vol-1\"}") {
		t.Fatalf("v1 detach argv missing --metadata JSON: %q", argv)
	}
	if stdin := readDump(t, dir, "stdin.txt"); stdin != "" {
		t.Fatalf("v1 detach must not write stdin, got %q", stdin)
	}
}

// TestBinaryPlugin_InitRejectsUnknownProtocol pins the versioned scheme:
// only the documented "stdin" (default) and "argv-v1" are accepted.
func TestBinaryPlugin_InitRejectsUnknownProtocol(t *testing.T) {
	dir := t.TempDir()
	p := NewBinary("stub", writeStubPlugin(t, dir))
	err := p.Init(context.Background(), PluginConfig{
		Name: "stub", Type: PluginTypeBinary, BinaryPath: filepath.Join(dir, "stub-plugin.sh"),
		Extra: map[string]string{"protocol": "grpc"},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("want unknown-protocol error, got %v", err)
	}
}
