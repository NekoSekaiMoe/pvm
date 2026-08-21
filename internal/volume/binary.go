package volume

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// binaryPluginTimeout bounds a single plugin process execution when the
// caller's context carries no deadline, so a hung plugin cannot hold the
// attach/detach path forever.
const binaryPluginTimeout = 30 * time.Second

// BinaryPlugin forks an external process per hook, speaking the
// newline-delimited JSON wire protocol over stdin/stdout — mirroring
// Cubelet/plugins/volume/binary.Driver.
type BinaryPlugin struct {
	name       string
	binaryPath string
	cfg        PluginConfig
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
	args := []string{
		"--op", "attach",
		"--sandbox-id", req.SandboxID,
		"--namespace", req.Namespace,
		"--volume-id", req.VolumeID,
		"--driver", req.Driver,
		"--ref-count", fmt.Sprintf("%d", req.RefCount),
		"--node-ref-first-attach", strconv.FormatBool(req.NodeRefFirstAttach),
		"--volume-base-dir", req.VolumeBaseDir,
	}
	in := pluginInput{PrivateData: req.PrivateData}
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
	args := []string{
		"--op", "detach",
		"--sandbox-id", req.SandboxID,
		"--namespace", req.Namespace,
		"--volume-id", req.VolumeID,
		"--driver", req.Driver,
		"--ref-count", fmt.Sprintf("%d", req.RefCount),
		"--node-ref-last-detach", strconv.FormatBool(req.NodeRefLastDetach),
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
	// Pipe the private payload over stdin: argv is world-readable via
	// /proc/<pid>/cmdline, so credentials must never be arguments.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("volume binary %q: stdin pipe: %w", p.binaryPath, err)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil // captured via ExitError only when set
	// Note: PrivateData/Metadata values are deliberately NOT included in any
	// error message below.
	if err := cmd.Start(); err != nil {
		stdin.Close()
		return nil, fmt.Errorf("volume binary %q: %w", p.binaryPath, err)
	}
	raw, _ := json.Marshal(in)
	if _, werr := stdin.Write(append(raw, '\n')); werr != nil {
		_ = cmd.Process.Kill()
		stdin.Close()
		return nil, fmt.Errorf("volume binary %q: write stdin: %w", p.binaryPath, werr)
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("volume binary %q %v: stderr: %w", p.binaryPath, args, ee)
		}
		return nil, fmt.Errorf("volume binary %q: %w", p.binaryPath, err)
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}
