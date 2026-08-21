package volume

import (
	"context"
	"fmt"
	"os"
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
	volLocks  map[string]*volumeLock       // volumeID -> per-volume lifecycle lock
	volLocksM sync.Mutex                   // guards volLocks and volumeLock.holders
}

// volumeLock pairs a per-volume lifecycle mutex with a holder count so the
// volLocks entry can be reclaimed once the last holder releases it — without
// reclamation the map would grow without bound (one entry per volume ID ever
// seen) on a long-lived host.
type volumeLock struct {
	sync.Mutex
	holders int // guarded by Manager.volLocksM
}

// lockFor registers the caller as a holder and returns the per-volume
// lifecycle lock, creating it on first use. Attach and Detach for the SAME
// volume serialize on it so plugin calls and count updates cannot interleave.
// The holder count is incremented while volLocksM is held and BEFORE the
// caller can touch the mutex, so a concurrent unlockFor can never observe a
// spurious zero and delete an entry another goroutine still waits on.
func (m *Manager) lockFor(volumeID string) *volumeLock {
	m.volLocksM.Lock()
	defer m.volLocksM.Unlock()
	l, ok := m.volLocks[volumeID]
	if !ok {
		l = &volumeLock{}
		m.volLocks[volumeID] = l
	}
	l.holders++
	return l
}

// unlockFor releases the lifecycle lock and drops the caller's holder
// registration, deleting the volLocks entry when the last holder is gone.
// Callers must pair exactly one unlockFor with each lockFor after a
// successful Lock.
func (m *Manager) unlockFor(volumeID string, l *volumeLock) {
	l.Unlock()
	m.volLocksM.Lock()
	l.holders--
	if l.holders <= 0 {
		delete(m.volLocks, volumeID)
	}
	m.volLocksM.Unlock()
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
		volLocks:  make(map[string]*volumeLock),
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
	// Same id rule as Attach/Detach, enforced at registration so an invalid
	// driver name is rejected up front rather than at first use.
	if !ValidateID(cfg.Name) {
		return fmt.Errorf("volume: invalid driver name %q (must match %s)", cfg.Name, volumeIDRe.String())
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
// sandboxID. The Manager validates the ids, takes the per-volume lifecycle
// lock FIRST, and only then reserves the refcount and fills
// RefCount/VolumeBaseDir/NodeRefFirstAttach — so the reservation order and
// the plugin call order can never disagree (the caller that reserved count 0
// is always the first plugin call), and no concurrent Detach can interleave
// its teardown between the reservation and the plugin call. The reservation
// is rolled back if the plugin or the HostPath containment check fails.
func (m *Manager) Attach(ctx context.Context, req *AttachRequest) (*AttachResult, error) {
	if req == nil {
		return nil, fmt.Errorf("volume: nil AttachRequest")
	}
	if !ValidateID(req.VolumeID) {
		return nil, fmt.Errorf("volume: invalid volume id %q (must match %s)", req.VolumeID, volumeIDRe.String())
	}
	if !ValidateID(req.Driver) {
		return nil, fmt.Errorf("volume: invalid driver %q (must match %s)", req.Driver, volumeIDRe.String())
	}
	m.mu.Lock()
	plugin, ok := m.plugins[req.Driver]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("volume: no plugin registered for driver %q", req.Driver)
	}

	// Serialize the whole lifecycle for this volume BEFORE reading the
	// refcount: reservation, plugin call and commit/rollback all happen
	// under vlock, in that order, for every caller.
	vlock := m.lockFor(req.VolumeID)
	vlock.Lock()
	defer m.unlockFor(req.VolumeID, vlock)

	// Reserve the count and compute first-attach under one lock.
	m.mu.Lock()
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
	if !ValidateID(req.VolumeID) {
		return fmt.Errorf("volume: invalid volume id %q (must match %s)", req.VolumeID, volumeIDRe.String())
	}
	if !ValidateID(req.Driver) {
		return fmt.Errorf("volume: invalid driver %q (must match %s)", req.Driver, volumeIDRe.String())
	}
	m.mu.Lock()
	plugin, ok := m.plugins[req.Driver]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("volume: no plugin registered for driver %q", req.Driver)
	}

	// Take the per-volume lifecycle lock before touching the refcount (same
	// vlock -> mu ordering as Attach) so a racing second Detach or Attach
	// cannot observe or reserve a half-committed transition.
	vlock := m.lockFor(req.VolumeID)
	vlock.Lock()
	defer m.unlockFor(req.VolumeID, vlock)

	m.mu.Lock()
	cur := m.refCounts[req.VolumeID]
	if cur == 0 {
		m.mu.Unlock()
		return fmt.Errorf("volume: detach without matching attach for %q", req.VolumeID)
	}
	post := cur - 1
	req.RefCount = post
	req.NodeRefLastDetach = post == 0
	// Reserve the detach: store post NOW so a racing second Detach (serialized
	// by the per-volume lock above) cannot reserve the same transition twice.
	m.refCounts[req.VolumeID] = post
	// Replay the metadata from the last Attach so the plugin can locate
	// resources.
	if req.Metadata == nil {
		if meta, ok := m.extraMeta[req.VolumeID]; ok {
			req.Metadata = meta
		}
	}
	m.mu.Unlock()

	if err := plugin.Detach(ctx, req); err != nil {
		// Roll back only this call's reservation; the previous state stands.
		m.mu.Lock()
		m.refCounts[req.VolumeID] = cur
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	if post == 0 {
		delete(m.attached, req.VolumeID)
		delete(m.extraMeta, req.VolumeID)
		// Match Attach's rollback: a fully-detached volume leaves no zero
		// entry behind in refCounts. RefCount keeps returning 0 for missing
		// keys, so this is hygiene, not a behavior change.
		delete(m.refCounts, req.VolumeID)
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

// validateHostPath enforces that hostPath resolves INSIDE baseDir after
// symlink resolution. A pure string-prefix check on the cleaned path is not
// enough: a plugin may return "<base>/link -> /etc" and the string check
// passes while the actual data lands outside the volume root.
func (m *Manager) validateHostPath(hostPath string) error {
	clean := filepath.Clean(hostPath)
	base := filepath.Clean(m.baseDir)
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return fmt.Errorf("volume: VolumeBaseDir %q not resolvable: %w", m.baseDir, err)
	}
	// Resolve symlinks of the nearest existing ancestor; trailing components
	// don't exist yet (the plugin creates them) so EvalSymlinks would fail
	// on the full path.
	resolved := resolveExisting(clean)
	if resolved == resolvedBase {
		return nil
	}
	if !strings.HasPrefix(resolved, resolvedBase+string(filepath.Separator)) {
		return fmt.Errorf("volume: HostPath %q must be inside VolumeBaseDir %q", hostPath, m.baseDir)
	}
	return nil
}

// resolveExisting returns p with all symlinks resolved for its longest
// existing prefix; non-existing trailing components are appended verbatim
// (they cannot carry symlinks yet).
func resolveExisting(p string) string {
	suffix := ""
	cur := p
	for {
		if _, err := os.Lstat(cur); err == nil {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the filesystem root without finding anything that
			// exists; nothing to resolve.
			return p
		}
		suffix = filepath.Join(filepath.Base(cur), suffix)
		cur = parent
	}
	resolved, err := filepath.EvalSymlinks(cur)
	if err != nil {
		// Raced deletion or unreadable ancestor: fall back to the lexical
		// path — containment then relies on the string check as before.
		return p
	}
	return filepath.Join(resolved, suffix)
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
