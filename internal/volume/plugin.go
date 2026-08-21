// Package volume implements a pluggable persistent-volume framework
// mirroring CubeSandbox's Cubelet/plugins/volume design (ref).
//
// Hooks split into Controller side (Create/Destroy) and Node side
// (Attach/Detach). In PVM's single-host UML mode the Controller is
// collapsed into the local Manager but the same four hooks and the
// refCount/volumeBaseDir containment rules are preserved.
//
// Binary plugins speak an explicitly versioned wire protocol (see
// binary.go): the hardened default pipes credentials over stdin (v2,
// "stdin"), while unmodified ref/examples/volume plugins such as
// cube-volume-cos.sh — which parse strict argv and never read stdin —
// are supported via the byte-compatible "argv-v1" opt-in:
//
//	extra = { protocol = "argv-v1" }
package volume

import (
	"context"
)

// PluginType mirrors Cubelet/plugins/volume.PluginType.
type PluginType string

const (
	PluginTypeBuiltin PluginType = "builtin"
	PluginTypeBinary  PluginType = "binary"
	PluginTypeRPC     PluginType = "rpc"
)

// PluginConfig mirrors Cubelet/plugins/volume.PluginConfig. Extra is
// forwarded to builtin plugins on Init.
type PluginConfig struct {
	Name       string            `toml:"name" json:"name"`
	Type       PluginType        `toml:"type" json:"type"`
	BinaryPath string            `toml:"binary_path" json:"binary_path"`
	SocketPath string            `toml:"socket_path" json:"socket_path"`
	Extra      map[string]string `toml:"extra" json:"extra"`
}

// AttachRequest mirrors Cubelet/plugins/volume.AttachRequest.
type AttachRequest struct {
	SandboxID string
	Namespace string
	VolumeID  string
	Driver    string
	// RefCount is the pre-attach count (0 == first attach on this host).
	RefCount int64
	// NodeRefFirstAttach is true when this call transitions 0→1 on the node.
	NodeRefFirstAttach bool
	VolumeBaseDir      string
	PrivateData        string
}

// AttachResult mirrors Cubelet/plugins/volume.AttachResult.
type AttachResult struct {
	VolumeID string
	HostPath string
	Metadata map[string]string
}

// DetachRequest mirrors Cubelet/plugins/volume.DetachRequest.
type DetachRequest struct {
	SandboxID string
	Namespace string
	VolumeID  string
	Driver    string
	Metadata  map[string]string
	// RefCount is the post-detach count (0 == last detach).
	RefCount int64
	// NodeRefLastDetach is true when this call transitions 1→0 on the node.
	NodeRefLastDetach bool
}

// VolumePlugin is the single interface every plugin must satisfy,
// regardless of loading mechanism.
type VolumePlugin interface {
	Name() string
	PluginType() PluginType
	Init(ctx context.Context, cfg PluginConfig) error
	Attach(ctx context.Context, req *AttachRequest) (*AttachResult, error)
	Detach(ctx context.Context, req *DetachRequest) error
	Close() error
}
