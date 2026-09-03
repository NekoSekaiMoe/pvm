package volume

// rpc.go — long-running RPC volume plugins over a Unix socket.
//
// Protocol: newline-delimited JSON over a stream Unix socket. One request
// line in, one response line out, then the connection is kept open for the
// next hook (a long-running plugin process, unlike the fork-per-hook
// binary plugins):
//
//	→ {"op":"attach","sandbox_id":"s","volume_id":"v","driver":"rpc1",
//	   "ref_count":1,"node_ref_first_attach":true,
//	   "volume_base_dir":"/data","private_data":"..."}
//	← {"volume_id":"v","host_path":"/data/rpc1-v","metadata":{...}}
//
//	→ {"op":"detach","sandbox_id":"s","volume_id":"v","driver":"rpc1",
//	   "metadata":{...},"ref_count":0,"node_ref_last_detach":true}
//	← {}
//
// A non-empty "error" field on the response line (or a non-zero exit of
// the socket) fails the hook. Timeouts bound every exchange so a hung
// plugin cannot wedge Attach/Detach.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// rpcPluginTimeout bounds one hook exchange.
const rpcPluginTimeout = 30 * time.Second

// rpcRequest is the wire form of a hook call.
type rpcRequest struct {
	Op                 string            `json:"op"`
	SandboxID          string            `json:"sandbox_id,omitempty"`
	Namespace          string            `json:"namespace,omitempty"`
	VolumeID           string            `json:"volume_id,omitempty"`
	Driver             string            `json:"driver,omitempty"`
	RefCount           int64             `json:"ref_count,omitempty"`
	NodeRefFirstAttach bool              `json:"node_ref_first_attach,omitempty"`
	NodeRefLastDetach  bool              `json:"node_ref_last_detach,omitempty"`
	VolumeBaseDir      string            `json:"volume_base_dir,omitempty"`
	PrivateData        string            `json:"private_data,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// rpcResponse is the wire form of a hook result.
type rpcResponse struct {
	VolumeID  string            `json:"volume_id,omitempty"`
	HostPath  string            `json:"host_path,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Error     string            `json:"error,omitempty"`
	ErrorData string            `json:"error_data,omitempty"`
}

// RPCPlugin speaks the unix-socket NDJSON protocol. One connection is
// dialed per hook (plugins are cheap to accept; a shared conn would need
// its own lifecycle and error recovery for little gain at PVM's scale).
type RPCPlugin struct {
	name       string
	socketPath string
}

// NewRPC returns an RPC plugin client for socketPath.
func NewRPC(name, socketPath string) *RPCPlugin {
	return &RPCPlugin{name: name, socketPath: socketPath}
}

func (p *RPCPlugin) Name() string           { return p.name }
func (p *RPCPlugin) PluginType() PluginType { return PluginTypeRPC }

func (p *RPCPlugin) Init(_ context.Context, cfg PluginConfig) error {
	if cfg.SocketPath == "" {
		return fmt.Errorf("volume rpc %q: socket_path required", p.name)
	}
	p.socketPath = cfg.SocketPath
	return nil
}

// call performs one request/response exchange.
func (p *RPCPlugin) call(ctx context.Context, req *rpcRequest) (*rpcResponse, error) {
	d := net.Dialer{Timeout: rpcPluginTimeout}
	conn, err := d.DialContext(ctx, "unix", p.socketPath)
	if err != nil {
		return nil, fmt.Errorf("volume rpc %q dial %s: %w", p.name, p.socketPath, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(rpcPluginTimeout)
	if d, ok := ctx.Deadline(); !ok || d.After(deadline) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	_ = conn.SetDeadline(deadline)

	line, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("volume rpc %q write: %w", p.name, err)
	}
	br := bufio.NewReader(conn)
	respLine, err := br.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("volume rpc %q read: %w", p.name, err)
	}
	var resp rpcResponse
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return nil, fmt.Errorf("volume rpc %q bad response: %w", p.name, err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("volume rpc %q: %s: %s", p.name, resp.Error, resp.ErrorData)
	}
	return &resp, nil
}

func (p *RPCPlugin) Attach(ctx context.Context, req *AttachRequest) (*AttachResult, error) {
	resp, err := p.call(ctx, &rpcRequest{
		Op:                 "attach",
		SandboxID:          req.SandboxID,
		Namespace:          req.Namespace,
		VolumeID:           req.VolumeID,
		Driver:             req.Driver,
		RefCount:           req.RefCount,
		NodeRefFirstAttach: req.NodeRefFirstAttach,
		VolumeBaseDir:      req.VolumeBaseDir,
		PrivateData:        req.PrivateData,
	})
	if err != nil {
		return nil, err
	}
	return &AttachResult{VolumeID: resp.VolumeID, HostPath: resp.HostPath, Metadata: resp.Metadata}, nil
}

func (p *RPCPlugin) Detach(ctx context.Context, req *DetachRequest) error {
	_, err := p.call(ctx, &rpcRequest{
		Op:                "detach",
		SandboxID:         req.SandboxID,
		Namespace:         req.Namespace,
		VolumeID:          req.VolumeID,
		Driver:            req.Driver,
		RefCount:          req.RefCount,
		NodeRefLastDetach: req.NodeRefLastDetach,
		Metadata:          req.Metadata,
	})
	return err
}

func (p *RPCPlugin) Close() error { return nil }
