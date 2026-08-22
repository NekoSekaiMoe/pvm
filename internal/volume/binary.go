package volume

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// binaryPluginTimeout bounds a single plugin process execution when the
// caller's context carries no deadline, so a hung plugin cannot hold the
// attach/detach path forever.
const binaryPluginTimeout = 30 * time.Second

// maxPluginStdout caps plugin stdout at 1 MiB: plugins are expected to emit
// a single small JSON object, and an unbounded buffer lets a misbehaving (or
// hostile) plugin exhaust host memory.
const maxPluginStdout = 1 << 20

// limitedBuffer collects up to max bytes of stdout; anything beyond sets
// overflow instead of failing the write (an error here would surface as an
// opaque exec.Wait error, hiding the real cause).
type limitedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.max {
		l.overflow = true
		return len(p), nil // swallowed; reported by the overflow check in run()
	}
	return l.buf.Write(p)
}

// BinaryPlugin forks an external process per hook, mirroring
// Cubelet/plugins/volume/binary.Driver from ref.
//
// # Wire protocol versions
//
// Two explicit, versioned calling conventions are supported; the plugin
// picks one via PluginConfig.Extra["protocol"] at Init time:
//
//	protocol = "stdin"    (default, v2 — PVM hardening)
//	protocol = "argv-v1"  (ref Cubelet byte-compatible)
//
// v2 (default) keeps credentials OUT of argv, because /proc/<pid>/cmdline
// is world-readable: argv carries only non-secret fields and the private
// payload is piped as a single JSON line over stdin:
//
//	attach argv: --op attach --sandbox-id --namespace --volume-id
//	             --driver --ref-count --node-ref-first-attach
//	             --volume-base-dir
//	detach argv: --op detach --sandbox-id --namespace --volume-id
//	             --driver --ref-count --node-ref-last-detach
//	stdin line:  {"private_data":"..."}   (attach)
//	             {"metadata":{...}}        (detach)
//
// v1 ("argv-v1") reproduces ref Cubelet's exact flag set so unmodified
// plugins from ref/examples/volume (e.g. cube-volume-cos.sh, whose strict
// parser dies on unknown flags and which never reads stdin) keep working:
//
//	attach argv: --op attach --sandbox-id --namespace --volume-id
//	             --ref-count --volume-base-dir [--private-data <str>]
//	             (--private-data omitted when empty, as in ref)
//	detach argv: --op detach --sandbox-id --namespace --volume-id
//	             --ref-count --metadata <json-object>
//
// Both versions exchange a single JSON object on stdout; exit code 0 plus
// an empty "error" field means success.
type BinaryPlugin struct {
	name       string
	binaryPath string
	cfg        PluginConfig
	legacyArgv bool // v1 "argv-v1": ref Cubelet wire format
}

func NewBinary(name, binaryPath string) *BinaryPlugin {
	return &BinaryPlugin{name: name, binaryPath: binaryPath}
}

func (p *BinaryPlugin) Name() string           { return p.name }
func (p *BinaryPlugin) PluginType() PluginType { return PluginTypeBinary }

func (p *BinaryPlugin) Init(_ context.Context, cfg PluginConfig) error {
	p.name = cfg.Name
	p.cfg = cfg
	if cfg.BinaryPath != "" {
		p.binaryPath = cfg.BinaryPath
	}
	if p.binaryPath == "" {
		return fmt.Errorf("volume binary: binary_path required for driver %q", cfg.Name)
	}
	if !filepath.IsAbs(p.binaryPath) {
		return fmt.Errorf("volume binary: binary_path must be absolute, got %q", p.binaryPath)
	}
	// Explicit protocol versioning (see the wire-protocol block above):
	// "stdin" is the hardened default; "argv-v1" opts into the ref Cubelet
	// wire format. Unknown values fail fast instead of guessing.
	switch cfg.Extra["protocol"] {
	case "", "stdin":
		p.legacyArgv = false
	case "argv-v1":
		p.legacyArgv = true
		log.Printf("[warn] volume binary %q: protocol=argv-v1 puts credentials in argv "+
			"(world-readable via /proc/<pid>/cmdline); use protocol=stdin if the plugin supports it",
			p.binaryPath)
	default:
		return fmt.Errorf("volume binary: unknown protocol %q (want %q or %q)",
			cfg.Extra["protocol"], "stdin", "argv-v1")
	}
	return nil
}

// pluginInput is the private payload piped to the plugin process over stdin:
// credentials (PrivateData, Metadata) never appear in argv, which is world-
// readable via /proc/<pid>/cmdline.
type pluginInput struct {
	PrivateData string            `json:"private_data,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func (p *BinaryPlugin) Attach(ctx context.Context, req *AttachRequest) (*AttachResult, error) {
	in := pluginInput{PrivateData: req.PrivateData}
	var args []string
	if p.legacyArgv {
		// v1: ref Cubelet byte-compatibility. PrivateData rides argv (the
		// documented v1 trade-off) and is omitted when empty, like ref;
		// nothing is written to stdin.
		args = []string{
			"--op", "attach",
			"--sandbox-id", req.SandboxID,
			"--namespace", req.Namespace,
			"--volume-id", req.VolumeID,
			"--ref-count", fmt.Sprintf("%d", req.RefCount),
			"--volume-base-dir", req.VolumeBaseDir,
		}
		if req.PrivateData != "" {
			args = append(args, "--private-data", req.PrivateData)
		}
	} else {
		args = []string{
			"--op", "attach",
			"--sandbox-id", req.SandboxID,
			"--namespace", req.Namespace,
			"--volume-id", req.VolumeID,
			"--driver", req.Driver,
			"--ref-count", fmt.Sprintf("%d", req.RefCount),
			"--node-ref-first-attach", strconv.FormatBool(req.NodeRefFirstAttach),
			"--volume-base-dir", req.VolumeBaseDir,
		}
	}
	out, err := p.run(ctx, args, in)
	if err != nil {
		return nil, err
	}
	var res struct {
		HostPath string            `json:"host_path"`
		Metadata map[string]string `json:"metadata"`
		Error    string            `json:"error"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("volume binary attach: unmarshal: %w (raw %q)", err, string(out))
	}
	if res.Error != "" {
		return nil, fmt.Errorf("volume binary attach: %s", res.Error)
	}
	return &AttachResult{
		VolumeID: req.VolumeID,
		HostPath: res.HostPath,
		Metadata: res.Metadata,
	}, nil
}

func (p *BinaryPlugin) Detach(ctx context.Context, req *DetachRequest) error {
	in := pluginInput{Metadata: req.Metadata}
	var args []string
	if p.legacyArgv {
		// v1: ref Cubelet byte-compatibility; Metadata rides argv as a JSON
		// object, stdin stays closed.
		metaJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return fmt.Errorf("volume binary detach: metadata: %w", err)
		}
		args = []string{
			"--op", "detach",
			"--sandbox-id", req.SandboxID,
			"--namespace", req.Namespace,
			"--volume-id", req.VolumeID,
			"--ref-count", fmt.Sprintf("%d", req.RefCount),
			"--metadata", string(metaJSON),
		}
	} else {
		args = []string{
			"--op", "detach",
			"--sandbox-id", req.SandboxID,
			"--namespace", req.Namespace,
			"--volume-id", req.VolumeID,
			"--driver", req.Driver,
			"--ref-count", fmt.Sprintf("%d", req.RefCount),
			"--node-ref-last-detach", strconv.FormatBool(req.NodeRefLastDetach),
		}
	}
	out, err := p.run(ctx, args, in)
	if err != nil {
		return err
	}
	var res struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		// Empty stdout on success (exit 0) is also accepted.
		if len(bytes.TrimSpace(out)) == 0 {
			return nil
		}
		return fmt.Errorf("volume binary detach: unmarshal: %w (raw %q)", err, string(out))
	}
	if res.Error != "" {
		return fmt.Errorf("volume binary detach: %s", res.Error)
	}
	return nil
}

func (p *BinaryPlugin) Close() error { return nil }

func (p *BinaryPlugin) run(ctx context.Context, args []string, in pluginInput) ([]byte, error) {
	// Bound execution even when the caller supplied context.Background().
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, binaryPluginTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, p.binaryPath, args...)
	// v2 pipes the private payload over stdin: argv is world-readable via
	// /proc/<pid>/cmdline, so credentials must never be arguments. In v1
	// (argv-v1) the payload rides argv per the ref protocol and stdin is
	// never written — legacy plugins do not read it.
	var stdin io.WriteCloser
	if !p.legacyArgv {
		var err error
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("volume binary %q: stdin pipe: %w", p.binaryPath, err)
		}
	}
	var stdout limitedBuffer
	stdout.max = maxPluginStdout
	cmd.Stdout = &stdout
	cmd.Stderr = nil // captured via ExitError only when set
	// Note: PrivateData/Metadata values are deliberately NOT included in any
	// error message below — in v1 they are part of args, so args themselves
	// must not be printed either.
	if err := cmd.Start(); err != nil {
		if stdin != nil {
			stdin.Close()
		}
		return nil, fmt.Errorf("volume binary %q: %w", p.binaryPath, err)
	}
	if stdin != nil {
		raw, _ := json.Marshal(in)
		if _, werr := stdin.Write(append(raw, '\n')); werr != nil {
			_ = cmd.Process.Kill()
			stdin.Close()
			return nil, fmt.Errorf("volume binary %q: write stdin: %w", p.binaryPath, werr)
		}
		stdin.Close()
	}
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("volume binary %q: %w", p.binaryPath, ee)
		}
		return nil, fmt.Errorf("volume binary %q: %w", p.binaryPath, err)
	}
	if stdout.overflow {
		return nil, fmt.Errorf("volume binary %q: stdout exceeded %d bytes", p.binaryPath, maxPluginStdout)
	}
	return bytes.TrimSpace(stdout.buf.Bytes()), nil
}
