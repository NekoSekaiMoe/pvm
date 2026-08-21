package volume

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// DefaultVolumeBaseDir is the parent directory all plugin hostPaths must
// live under. Overridable via PVM_VOLUME_BASE_DIR (mirrors
// Cubelet's volume_plugin_base_dir / PVM_VOLUME_BASE_DIR).
const DefaultVolumeBaseDir = "/var/lib/uml-container/volumes"

// Manager routes Attach/Detach by driver name and maintains per-volume
// ref counts (node-local, single-host). It mirrors
// Cubelet/plugins/volume.Manager at single-host scale.
type Manager struct {
	mu        sync.Mutex
	plugins   map[string]VolumePlugin // driver -> plugin
	baseDir   string
	refCounts map[string]int64             // volumeID -> current count
	attached  map[string]*AttachResult     // volumeID -> last AttachResult (for Detach metadata)
	extraMeta map[string]map[string]string // volumeID -> user metadata passthrough
}

// NewManager creates a Manager. baseDir defaults to DefaultVolumeBaseDir
// when empty.
func NewManager(baseDir string) *Manager {
	if baseDir == "" {
		baseDir = DefaultVolumeBaseDir
	}
	return &Manager{
		plugins:   make(map[string]VolumePlugin),
		baseDir:   baseDir,
		refCounts: make(map[string]int64),
		attached:  make(map[string]*AttachResult),
		extraMeta: make(map[string]map[string]string),
	}
}

// BaseDir returns the configured volume base dir (for spec validation / tests).
func (m *Manager) BaseDir() string { return m.baseDir }

// Register installs a plugin under its Name(). The driver name must be unique
// (mirrors Cubelet's "name must be unique among volume_plugins" rule).
func (m *Manager) Register(ctx context.Context, cfg PluginConfig, p VolumePlugin) error {
	if cfg.Name == "" {
		return fmt.Errorf("volume: plugin name required")
	}
	if p == nil {
		return fmt.Errorf("volume: nil plugin for driver %q", cfg.Name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.plugins[cfg.Name]; exists {
		return fmt.Errorf("volume: driver %q already registered", cfg.Name)
	}
	if err := p.Init(ctx, cfg); err != nil {
		return fmt.Errorf("volume: init plugin %q: %w", cfg.Name, err)
	}
	m.plugins[cfg.Name] = p
	return nil
}

// MustRegister is like Register but panics on error (for init-time wiring).
func (m *Manager) MustRegister(ctx context.Context, cfg PluginConfig, p VolumePlugin) {
	if err := m.Register(ctx, cfg, p); err != nil {
		panic(err)
	}
}

// Registered returns the sorted driver names (for diagnostics).
func (m *Manager) Registered() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.plugins))
	for k := range m.plugins {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Attach provisions (or reuses) the host path for volumeID on behalf of
// sandboxID. The Manager validates the ids, reserves the refcount and fills
// RefCount/VolumeBaseDir/NodeRefFirstAttach under one lock (so concurrent
// Attaches for the same volume cannot both observe the pre-attach count),
// delegates to the plugin, and rolls the reservation back if the plugin or
// the HostPath containment check fails.
func (m *Manager) Attach(ctx context.Context, req *AttachRequest) (*AttachResult, error) {
	if req == nil {
		return nil, fmt.Errorf("volume: nil AttachRequest")
	}
	if !volumeIDRe.MatchString(req.VolumeID) {
		return nil, fmt.Errorf("volume: invalid volume id %q (must match %s)", req.VolumeID, volumeIDRe.String())
	}
	if !volumeIDRe.MatchString(req.Driver) {
		return nil, fmt.Errorf("volume: invalid driver %q (must match %s)", req.Driver, volumeIDRe.String())
	}
	m.mu.Lock()
	plugin, ok := m.plugins[req.Driver]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("volume: no plugin registered for driver %q", req.Driver)
	}
	// Reserve the count and compute first-attach under the same lock.
	req.RefCount = m.refCounts[req.VolumeID]
	m.refCounts[req.VolumeID]++
	req.NodeRefFirstAttach = req.RefCount == 0
	req.VolumeBaseDir = m.baseDir
	m.mu.Unlock()

	// Roll back the reservation on any failure below.
	rollback := func() {
		m.mu.Lock()
		if m.refCounts[req.VolumeID] > 0 {
			m.refCounts[req.VolumeID]--
		}
		if m.refCounts[req.VolumeID] <= 0 {
			delete(m.refCounts, req.VolumeID)
		}
		m.mu.Unlock()
	}

	res, err := plugin.Attach(ctx, req)
	if err != nil {
		rollback()
		return nil, err
	}
	if res == nil {
		rollback()
		return nil, fmt.Errorf("volume: plugin %q returned nil AttachResult", req.Driver)
	}
	if res.HostPath == "" {
		rollback()
		return nil, fmt.Errorf("volume: plugin %q returned empty HostPath", req.Driver)
	}
	if err := m.validateHostPath(res.HostPath); err != nil {
		rollback()
		return nil, err
	}

	m.mu.Lock()
	m.attached[req.VolumeID] = res
	// copy metadata for Detach replay
	if res.Metadata != nil {
		cp := make(map[string]string, len(res.Metadata))
		for k, v := range res.Metadata {
			cp[k] = v
		}
		m.extraMeta[req.VolumeID] = cp
	}
	m.mu.Unlock()

	return res, nil
}

// Detach tears down the attachment. The Manager computes the post-detach
// count and replays metadata, delegates to the plugin, and only commits the
// refcount/attached/extraMeta changes after the plugin succeeds — a plugin
// error leaves the previous state intact.
func (m *Manager) Detach(ctx context.Context, req *DetachRequest) error {
	if req == nil {
		return fmt.Errorf("volume: nil DetachRequest")
	}
	if !volumeIDRe.MatchString(req.VolumeID) {
		return fmt.Errorf("volume: invalid volume id %q (must match %s)", req.VolumeID, volumeIDRe.String())
	}
	if !volumeIDRe.MatchString(req.Driver) {
		return fmt.Errorf("volume: invalid driver %q (must match %s)", req.Driver, volumeIDRe.String())
	}
	m.mu.Lock()
	plugin, ok := m.plugins[req.Driver]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("volume: no plugin registered for driver %q", req.Driver)
	}
	cur := m.refCounts[req.VolumeID]
	if cur == 0 {
		m.mu.Unlock()
		return fmt.Errorf("volume: detach without matching attach for %q", req.VolumeID)
	}
	post := cur - 1
	req.RefCount = post
	req.NodeRefLastDetach = post == 0
	// Replay the metadata from the last Attach so the plugin can locate
	// resources. State is NOT mutated yet.
	if req.Metadata == nil {
		if meta, ok := m.extraMeta[req.VolumeID]; ok {
			req.Metadata = meta
		}
	}
	m.mu.Unlock()

	if err := plugin.Detach(ctx, req); err != nil {
		return err // state untouched
	}

	m.mu.Lock()
	m.refCounts[req.VolumeID] = post
	if post == 0 {
		delete(m.attached, req.VolumeID)
		delete(m.extraMeta, req.VolumeID)
	}
	m.mu.Unlock()
	return nil
}

// RefCount returns the current node-local ref count for volumeID.
func (m *Manager) RefCount(volumeID string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refCounts[volumeID]
}

// HostPath returns the last AttachResult HostPath for volumeID (or empty).
func (m *Manager) HostPath(volumeID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.attached[volumeID]; ok {
		return r.HostPath
	}
	return ""
}

func (m *Manager) validateHostPath(hostPath string) error {
	clean := filepath.Clean(hostPath)
	base := filepath.Clean(m.baseDir)
	// Must be inside baseDir: either equal or prefixed with baseDir+"/"
	if clean == base {
		return nil
	}
	if !strings.HasPrefix(clean, base+string(filepath.Separator)) {
		return fmt.Errorf("volume: HostPath %q must be inside VolumeBaseDir %q", hostPath, m.baseDir)
	}
	return nil
}

// Close releases all registered plugins.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for name, p := range m.plugins {
		if err := p.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("volume: close plugin %q: %w", name, err)
		}
	}
	return firstErr
}
