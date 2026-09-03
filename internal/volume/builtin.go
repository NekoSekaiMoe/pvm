package volume

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BuiltinPlugin is a host-directory plugin compiled into the binary.
// It is the always-registered "builtin" PluginType.
//
// Attach creates <VolumeBaseDir>/<driver>-<volumeID> on first attach (mkdir -p)
// and reuses it thereafter. Detach is a no-op until the last holder leaves
// (it never deletes persistent data, matching Detach scope rule #4).
type BuiltinPlugin struct {
	name string
	cfg  PluginConfig
}

func NewBuiltin(name string) *BuiltinPlugin {
	return &BuiltinPlugin{name: name}
}

func (p *BuiltinPlugin) Name() string           { return p.name }
func (p *BuiltinPlugin) PluginType() PluginType { return PluginTypeBuiltin }

func (p *BuiltinPlugin) Init(_ context.Context, cfg PluginConfig) error {
	p.name = cfg.Name
	p.cfg = cfg
	return nil
}

func (p *BuiltinPlugin) Attach(_ context.Context, req *AttachRequest) (*AttachResult, error) {
	// Explicit host-directory mount: bind the operator-supplied directory
	// as-is (it must already exist — the Manager's whitelist validation
	// checked that). Metadata records the origin for auditability.
	if req.HostPath != "" {
		return &AttachResult{
			VolumeID: req.VolumeID,
			HostPath: req.HostPath,
			Metadata: map[string]string{"hostPath": req.HostPath, "origin": "explicit"},
		}, nil
	}
	if req.VolumeBaseDir == "" {
		return nil, fmt.Errorf("volume builtin: VolumeBaseDir required")
	}
	hostPath := filepath.Join(req.VolumeBaseDir, fmt.Sprintf("%s-%s", req.Driver, req.VolumeID))
	// Defense in depth: Join cleans the path, so a hostile id/driver could
	// still escape the base directory. Never create anything outside it.
	clean := filepath.Clean(hostPath)
	base := filepath.Clean(req.VolumeBaseDir)
	if clean != base && !strings.HasPrefix(clean, base+string(filepath.Separator)) {
		return nil, fmt.Errorf("volume builtin: host path %q escapes VolumeBaseDir %q", hostPath, req.VolumeBaseDir)
	}
	// Idempotent mkdir on every attach: concurrent first-time attaches both
	// need the directory, and NodeRefFirstAttach (not RefCount==0) carries
	// first-attach semantics.
	if err := os.MkdirAll(hostPath, 0755); err != nil {
		return nil, fmt.Errorf("volume builtin: mkdir %s: %w", hostPath, err)
	}
	return &AttachResult{
		VolumeID: req.VolumeID,
		HostPath: hostPath,
		Metadata: map[string]string{"hostPath": hostPath},
	}, nil
}

func (p *BuiltinPlugin) Detach(_ context.Context, req *DetachRequest) error {
	// Persistent data is never deleted on Detach (rule #4); host mount stays
	// until volume delete. Only release bookkeeping is done in Manager.
	_ = req
	return nil
}

func (p *BuiltinPlugin) Close() error { return nil }
