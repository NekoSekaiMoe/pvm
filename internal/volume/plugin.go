// Package volume implements a pluggable persistent-volume framework.
//
// Hooks split into a Controller side (Create/Destroy) and a Node side
// (Attach/Detach). In PVM's single-host UML mode the Controller is
// collapsed into the local Manager, but the same four hooks and the
// refCount/volumeBaseDir containment rules are preserved.
//
// Plugin loading mechanisms (PluginType): "builtin" (compiled in: the
// host-dir driver and the s3fs-backed s3 driver), "binary" (fork per
// hook) and "rpc" (long-running Unix-socket NDJSON server). Binary
// plugins speak an explicitly versioned wire protocol (see binary.go):
// the hardened default pipes credentials over stdin (v2, "stdin"),
// while strict-argv legacy scripts are supported via the byte-compatible
// "argv-v1" opt-in:
//
//	extra = { protocol = "argv-v1" }
package volume

import (
	"context"
)

// PluginType selects the plugin loading mechanism.
type PluginType string

const (
	PluginTypeBuiltin PluginType = "builtin"
	PluginTypeBinary  PluginType = "binary"
	PluginTypeRPC     PluginType = "rpc"
)

// PluginConfig configures one plugin registration. Extra is
// forwarded to builtin plugins on Init.
type PluginConfig struct {
	Name       string            `toml:"name" json:"name"`
	Type       PluginType        `toml:"type" json:"type"`
	BinaryPath string            `toml:"binary_path" json:"binary_path"`
	SocketPath string            `toml:"socket_path" json:"socket_path"`
	Extra      map[string]string `toml:"extra" json:"extra"`
}

// AttachRequest is the Node-side attach hook input.
type AttachRequest struct {
	SandboxID string
	Namespace string
	VolumeID  string
	Driver    string
	// HostPath, when non-empty, requests an EXPLICIT host-directory mount
	// (builtin driver only): the pre-existing host dir is bound into the
	// guest instead of a VolumeBaseDir-backed path. Gated on the
	// deployment-wide PVM_HOST_MOUNT_PREFIXES whitelist — see hostmount.go.
	HostPath string
	// RefCount is the pre-attach count (0 == first attach on this host).
	RefCount int64
	// NodeRefFirstAttach is true when this call transitions 0→1 on the node.
	NodeRefFirstAttach bool
	VolumeBaseDir      string
	PrivateData        string
}

// AttachResult is the Node-side attach hook output.
type AttachResult struct {
	VolumeID string
	HostPath string
	Metadata map[string]string
}

// DetachRequest is the Node-side detach hook input.
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
