package container

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"
	"uml-container/internal/audit"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/cow"
	"uml-container/internal/identity"
	"uml-container/internal/log"
	"uml-container/internal/network/egress"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/uml"
	"uml-container/internal/vhost"
)

type ContextKey string

const (
	KeyInteractive ContextKey = "interactive"
	KeyVolumeHost  ContextKey = "volume_host"
	KeyVolumeGuest ContextKey = "volume_guest"
)

// Manager launches UML sandboxes. It has two entry points:
//   - Start: the legacy/umlctl path. Takes a flat config.ContainerConfig and
//     just boots a kernel with cgroup limits. No policy planes.
//   - StartTask: the agentpvm path. Takes a validated spec.TaskSpec (the full
//     control contract from plan.md §9), drives the lifecycle FSM, and wires
//     identity / egress / audit / approval / artifact-gate / incident.
type Manager struct {
	Launcher uml.Launcher

	// Control planes (optional; nil = that plane is a no-op). Wired by the
	// controller for StartTask. The legacy Start path ignores these.
	Broker          *identity.Broker
	Egress          *egress.Gateway
	IncidentHandler IncidentHooks

	// OnProvisioned is called once the sandbox process is up, with the task id,
	// pid and the host-side identity token (if any). Used by the controller to
	// register task->pid for incident hooks and to deliver the token into the
	// sandbox via its init contract.
	OnProvisioned func(taskID string, pid int, token string)
}

// IncidentHooks is the subset of the incident controller the manager needs to
// notify on resource events (budget exhausted etc). Kept as an interface to
// avoid an import cycle (incident imports state; manager imports state too,
// but we don't want manager -> incident).
type IncidentHooks interface {
	OnBudgetExceeded(taskID string)
}

func NewManager(launcher uml.Launcher) *Manager {
	if launcher == nil {
		launcher = &uml.DefaultLauncher{}
	}
	return &Manager{Launcher: launcher}
}

// Start is the legacy entry point used by umlctl. It boots a UML kernel with
// the given flat config, sets up cgroup limits, and records legacy status
// (running/stopped/exited) in state.json. It does NOT engage the control planes.
func (m *Manager) Start(ctx context.Context, cfg *config.ContainerConfig) error {
	args := buildLegacyArgs(ctx, cfg)

	var logFile *os.File
	if interactive, _ := ctx.Value(KeyInteractive).(bool); !interactive {
		var err error
		logFile, err = log.SetupConsoleLog(cfg.ID)
		if err == nil {
			defer logFile.Close()
		} else {
			fmt.Printf("Warning: could not setup log file: %v\n", err)
		}
	}

	st, err := state.LoadState(cfg.ID)
	if err != nil {
		st = &state.ContainerState{ID: cfg.ID, Name: cfg.Name, StartedAt: time.Now()}
	}
	// legacy path writes legacy status strings; FSM is not engaged here.
	if st.Status == "" {
		st.Status = state.StatusRunning
	} else {
		st.Status = state.StatusRunning
	}
	st.PID = 0
	if saveErr := state.SaveState(cfg.ID, st); saveErr != nil {
		fmt.Printf("Warning: failed to save state: %v\n", saveErr)
	}

	pid, p, err := m.Launcher.Start(ctx, cfg.Kernel, args, logFile)
	st.PID = pid
	if err != nil {
		st.Status = state.StatusExited
		state.SaveState(cfg.ID, st)
		return err
	}

	cg := cgroup.NewManager()
	if setupErr := cg.Setup(cfg.ID, pid, cfg.MemoryBytes, cfg.CPU); setupErr != nil {
		fmt.Printf("Warning: failed to setup cgroup limits for %s: %v\n", cfg.ID, setupErr)
	}

	st.Status = state.StatusRunning
	state.SaveState(cfg.ID, st)

	if m.OnProvisioned != nil {
		m.OnProvisioned(cfg.ID, pid, "")
	}

	err = m.Launcher.Wait(p)
	if err != nil {
		st.Status = state.StatusExited
	} else {
		st.Status = state.StatusStopped
	}
	state.SaveState(cfg.ID, st)
	return err
}

// StartTask is the agentpvm entry point. It consumes a TaskSpec, drives the
// lifecycle FSM through Provisioning->Ready->Running, sets up the control
// planes (identity token, egress policy, audit records), provisions a qcow2
// overlay + vhost-user-blk backend, then boots the UML kernel. On exit it
// transitions the FSM toward Completed/Failed.
//
// taskID, if empty, is derived from the spec's Runtime.Name.
func (m *Manager) StartTask(ctx context.Context, taskID string, s *spec.TaskSpec) error {
	if s == nil {
		return fmt.Errorf("container: nil TaskSpec")
	}
	if taskID == "" {
		taskID = s.Runtime.Name
	}
	if taskID == "" {
		return fmt.Errorf("container: no task id (spec.runtime.name empty and no id given)")
	}
	// Defense in depth: validate taskID before it reaches the filesystem. The
	// caller (agentpvm) already enforces this, but StartTask is a public entry
	// point and must not trust its input for path-derivation (audit.Open and
	// state.ContainerDir both join taskID into host paths).
	if !idRegexp.MatchString(taskID) {
		return fmt.Errorf("container: invalid task id %q (must match %s)", taskID, idRegexp.String())
	}

	// Open the audit ledger for this task. Lives OUTSIDE the sandbox dir.
	ledger, err := audit.Open(taskID)
	if err != nil {
		return fmt.Errorf("container: open audit ledger: %w", err)
	}

	// Load/create lifecycle state early so any subsequent failure can flip it
	// to Failed consistently (including the spec-evidence append below).
	st, loadErr := state.LoadState(taskID)
	if loadErr != nil {
		// A non-nil error here means the state file exists but is corrupt or
		// unreadable, NOT that the task is new (a missing file returns nil,
		// nil). Discarding it silently would lose the prior transition history
		// with no trace; log it so an operator can distinguish a fresh task
		// from a state-loss event. We still proceed with a fresh state because
		// the task cannot run without one, and the audit ledger is the
		// tamper-evident record of what actually happened.
		log.Default().Warnf("container: load existing state for %s failed (starting fresh): %v", taskID, loadErr)
	}
	if st == nil {
		st = &state.ContainerState{ID: taskID, Name: s.Runtime.Name, Tenant: s.Tenant, Caller: s.Caller, StartedAt: time.Now()}
	}
	st.Name = s.Runtime.Name
	st.Tenant = s.Tenant
	st.Caller = s.Caller
	st.SpecFP = s.Fingerprint()
	st.Status = state.StatusPending
	state.SaveState(taskID, st)

	// Record the SPEC+VERSION evidence (plan.md §14.2 phase 02). This is
	// authorization evidence: a task MUST NOT start without it on disk. A
	// warn-and-continue path here would let a sandbox run with no auditable
	// spec trail, so fail fast (matching the audit.Open failure above).
	if err := ledger.Append(audit.Record{
		Phase:    audit.PhaseSpec,
		Subject:  s.Caller,
		Action:   "taskspec",
		Params:   map[string]interface{}{"fingerprint": s.Fingerprint(), "version": s.Version},
		Decision: audit.DecisionAllow,
		Reason:   "taskspec loaded",
	}); err != nil {
		_ = st.Transition(state.StatusFailed, state.ActorController, "audit spec append failed: "+err.Error())
		state.SaveState(taskID, st)
		return fmt.Errorf("container: audit taskspec for %s: %w", taskID, err)
	}

	// Provisioning: create overlay, start vhost daemon, set up network+policy.
	if err := st.Transition(state.StatusProvisioning, state.ActorController, "start task"); err != nil {
		return err
	}
	state.SaveState(taskID, st)

	// Provision the block device the kernel will mount. Two paths, selected by
	// Kernel.UseVhostBlk:
	//
	//   - vhost path (UseVhostBlk=true): create a per-task qcow2 CoW overlay on
	//     top of the (qcow2) base and serve it via qemu-storage-daemon over
	//     vhost-user-blk (virtio_uml.device). This is the CoW-isolated path.
	//     The base backing may be raw or qcow2 (sniffed by cow.CreateOverlay).
	//   - ubd path (UseVhostBlk=false): mount the BaseImage directly as
	//     ubd0=<base>. No CoW, no vhost. Both paths use the vec0 network
	//     transport (the only UML net transport in Linux >= 6.16, see todo.md);
	//     which block backend you pick no longer affects networking.
	dir, err := state.ContainerDir(taskID)
	if err != nil {
		return fmt.Errorf("container: container dir: %w", err)
	}
	overlayPath := s.Workspace.Overlay
	if overlayPath == "" {
		overlayPath = fmt.Sprintf("%s/rootfs.qcow2", dir)
	}
	// resolvedRootfs is the single source of truth for the block device the
	// kernel mounts. It is forwarded into buildTaskArgs so the kernel command
	// line and the overlay we actually created cannot drift apart.
	resolvedRootfs := ""
	overlayCreated := false // true only when we created a qcow2 overlay (the compact path)
	if s.Workspace.BaseImage != "" {
		if s.Kernel.UseVhostBlk {
			// vhost path: wrap the qcow2 base in a per-task qcow2 overlay.
			resolvedRootfs = overlayPath
			if err := cow.CreateOverlay(ctx, s.Workspace.BaseImage, overlayPath); err != nil {
				_ = ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "overlay", Decision: audit.DecisionDeny, Reason: "qcow2 overlay failed: " + err.Error()})
				_ = st.Transition(state.StatusFailed, state.ActorController, "overlay creation failed: "+err.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: create qcow2 overlay for %s: %w", taskID, err)
			}
			overlayCreated = true
		} else {
			// ubd path: mount the base directly (no CoW). Works with raw or
			// qcow2-as-flat-file; ubd reads raw bytes, so callers normally pass
			// a raw ext4 image here. Recorded as a constrained isolation level.
			resolvedRootfs = s.Workspace.BaseImage
			_ = ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "rootfs", Decision: audit.DecisionConstrain, Reason: "ubd backend mounts base directly (no qcow2 CoW)"})
		}
	}

	// vhost-user-blk backend over the overlay.
	var sockPath string
	var vhostBackend io.Closer
	var egressAddr string // host:port of this task's dedicated egress listener
	if s.Kernel.UseVhostBlk && s.Workspace.BaseImage != "" {
		sock, backend, err := vhost.StartBlk(taskID, resolvedRootfs)
		if err != nil {
			_ = st.Transition(state.StatusFailed, state.ActorController, "vhost daemon failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: vhost: %w", err)
		}
		sockPath = sock
		vhostBackend = backend
		defer func() {
			if vhostBackend != nil {
				vhostBackend.Close()
			}
			// Unlink the socket file too: a stale vhost-blk.sock outlives the
			// backend and once fooled a test into reporting a successful boot
			// from file existence alone (see todo.md).
			_ = os.Remove(sockPath)
		}()
	}

	// Egress gateway policy (plan.md §4). The gateway is shared across tasks;
	// we register this task's allowlist. When an egress gateway is configured
	// we also open a per-task listener whose handler binds the task id by
	// closure, so attribution does NOT depend on the guest-supplied X-Task-Id
	// header (which the guest can forge). The listener port is forwarded into
	// the guest as the proxy address it must dial; the task id never crosses
	// the trust boundary.
	if m.Egress != nil && s.Network.Enabled {
		pol := &egress.Policy{
			AllowDomains:   s.Network.EgressAllowDomains,
			BlockDomains:   s.Network.EgressBlockDomains,
			MaxRequestBody: s.Network.MaxRequestBodyBytes,
		}
		m.Egress.SetPolicy(taskID, pol)
		if lp, err := m.Egress.ListenForTask(ctx, taskID); err == nil {
			defer lp.Close()
			egressAddr = lp.Addr()
		} else {
			// Without a per-task listener we cannot safely attribute traffic,
			// so fail closed rather than falling back to the forgeable header.
			_ = st.Transition(state.StatusFailed, state.ActorController, "egress listener failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: egress listener for %s: %w", taskID, err)
		}
	}

	// Identity: mint a short-lived token carrying the spec's scope. The token
	// string is returned to the caller via OnProvisioned so the controller can
	// inject it into the sandbox's init contract; long-lived secrets stay
	// host-side. A mint failure now propagates (the identity plane is not
	// optional once a Broker is wired).
	var tokenStr string
	if m.Broker != nil {
		ttl := spec.DefaultTokenTTL
		if s.Identity.TTL != "" {
			if d, err := time.ParseDuration(s.Identity.TTL); err == nil {
				ttl = d
			}
		}
		tok, err := m.Broker.Mint(s.Caller, s.Tenant, taskID, s.Identity.Scope, ttl)
		if err != nil {
			_ = st.Transition(state.StatusFailed, state.ActorController, "identity mint failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: mint identity token: %w", err)
		}
		tokenStr = tok
	}

	// Build kernel args from the TaskSpec. Pass the resolved rootfs so the
	// kernel command line matches what we actually provisioned. egressAddr is
	// the host:port of this task's dedicated egress listener (authoritative
	// attribution source); the task id is NOT exposed to the guest.
	args := buildTaskArgs(s, sockPath, resolvedRootfs, egressAddr)

	// Non-interactive (agent sandbox) => log to file under the task dir.
	logFile, _ := log.SetupConsoleLog(taskID)
	if logFile != nil {
		defer logFile.Close()
	}

	// Ready: sandbox process about to start.
	_ = st.Transition(state.StatusReady, state.ActorController, "provisioned")
	state.SaveState(taskID, st)

	pid, p, err := m.Launcher.Start(ctx, s.Kernel.Path, args, logFile)
	st.PID = pid
	if err != nil {
		_ = st.Transition(state.StatusFailed, state.ActorController, "launch failed: "+err.Error())
		state.SaveState(taskID, st)
		return err
	}

	// Resource limits.
	cg := cgroup.NewManager()
	memBytes := int64(0)
	if s.Runtime.Memory != "" {
		if b, err := config.ParseMemory(s.Runtime.Memory); err == nil {
			memBytes = b
		}
	}
	if setupErr := cg.Setup(taskID, pid, memBytes, s.Runtime.CPU); setupErr != nil {
		fmt.Printf("Warning: failed to setup cgroup limits for %s: %v\n", taskID, setupErr)
	}

	// Budget enforcement: wall-clock deadline.
	if s.Budget.MaxWallTime != "" {
		if d, err := time.ParseDuration(s.Budget.MaxWallTime); err == nil {
			st.Deadline = time.Now().Add(d)
			state.SaveState(taskID, st)
			go m.watchDeadline(ctx, taskID, st.Deadline)
		}
	}

	_ = st.Transition(state.StatusRunning, state.ActorController, "agent loop started")
	state.SaveState(taskID, st)

	if err := ledger.Append(audit.Record{
		Phase: audit.PhaseExec, Subject: s.Caller, Action: "task:start",
		Params:   map[string]interface{}{"pid": pid, "has_token": tokenStr != ""},
		Decision: audit.DecisionAllow, Reason: "sandbox running",
	}); err != nil {
		// task:start is the execution-phase authorization evidence. A sandbox
		// running without it is the same integrity gap as a missing spec row,
		// so fail closed (we already transitioned to Running; flip to Failed).
		_ = st.Transition(state.StatusFailed, state.ActorController, "audit task:start append failed: "+err.Error())
		state.SaveState(taskID, st)
		return fmt.Errorf("container: audit task:start for %s: %w", taskID, err)
	}

	if m.OnProvisioned != nil {
		m.OnProvisioned(taskID, pid, tokenStr)
	}

	// Block until the kernel exits.
	waitErr := m.Launcher.Wait(p)

	if waitErr != nil {
		_ = st.Transition(state.StatusFailed, state.ActorAgent, "exited with error: "+waitErr.Error())
	} else {
		// Move toward Review (artifact gate happens later, called by the
		// controller); for now we land in Review to await verification.
		_ = st.Transition(state.StatusReview, state.ActorAgent, "exited cleanly, awaiting review")
	}
	state.SaveState(taskID, st)

	// Post-stop overlay compaction. Only the vhost path creates an overlay, so
	// overlayCreated gates the whole thing (the ubd path mounts the base
	// directly and has nothing to compact). The guest has exited (Wait
	// returned) and no more I/O is in flight; close the vhost backend
	// explicitly so it is not holding the overlay file open while we rename
	// a rebuilt file over it. The deferred close becomes a no-op once we nil
	// vhostBackend here. A compact failure must NOT flip a clean task to
	// Failed — the task already exited — so it is logged + audited only.
	if s.Workspace.CompactOnExit && overlayCreated {
		if vhostBackend != nil {
			vhostBackend.Close()
			vhostBackend = nil
		}
		stats, cerr := cow.Compact(context.Background(), overlayPath)
		if cerr != nil {
			fmt.Printf("Warning: compact overlay for %s failed: %v\n", taskID, cerr)
			_ = ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "overlay_compact", Decision: audit.DecisionConstrain, Reason: "compact failed: " + cerr.Error()})
		} else {
			fmt.Printf("Overlay compacted for %s: %d -> %d bytes (%d clusters copied, %d zeroed, %d dropped)\n",
				taskID, stats.BeforeBytes, stats.AfterBytes, stats.ClustersCopied, stats.ClustersZeroed, stats.ClustersDropped)
			_ = ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "overlay_compact", Decision: audit.DecisionAllow, Reason: fmt.Sprintf("overlay compacted: %d -> %d bytes", stats.BeforeBytes, stats.AfterBytes)})
		}
	}
	return waitErr
}

// watchDeadline fires the incident hook when a task exceeds its wall budget.
func (m *Manager) watchDeadline(ctx context.Context, taskID string, deadline time.Time) {
	d := time.Until(deadline)
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-t.C:
		if m.IncidentHandler != nil {
			m.IncidentHandler.OnBudgetExceeded(taskID)
		}
	}
}

// buildLegacyArgs reproduces the original UML command-line for the umlctl path.
// Extracted from the pre-refactor Start() to keep behavior byte-identical.
func buildLegacyArgs(ctx context.Context, cfg *config.ContainerConfig) []string {
	args := []string{
		fmt.Sprintf("init=%s", cfg.Init),
		fmt.Sprintf("mem=%s", cfg.Memory),
	}
	if interactive, _ := ctx.Value(KeyInteractive).(bool); interactive {
		args = append(args, "con0=fd:0,fd:1")
		args = append(args, "con=null")
	}
	if cfg.UseVirtio && cfg.VhostUserSocket != "" {
		args = append(args, fmt.Sprintf("virtio_uml.device=%s:%d", cfg.VhostUserSocket, vhost.VirtioIDBlock))
		args = append(args, "root=/dev/vda")
	} else {
		args = append(args, fmt.Sprintf("ubd0=%s", cfg.Rootfs))
		args = append(args, "root=/dev/ubda")
	}
	args = append(args, "rw")
	// Network device: vec0 (see buildTaskArgs — legacy eth0=tuntap is gone in
	// Linux >= 6.16, only the vector transport remains).
	if cfg.NetworkTap != "" {
		args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,depth=128,gro=1", cfg.NetworkTap))
	}
	vHost, hasVHost := ctx.Value(KeyVolumeHost).(string)
	vGuest, hasVGuest := ctx.Value(KeyVolumeGuest).(string)
	if hasVHost && hasVGuest {
		args = append(args, fmt.Sprintf("hostfs_volume=%s:%s", vHost, vGuest))
	}
	return args
}

// buildTaskArgs builds the UML command-line from a TaskSpec. Mirrors the legacy
// path but reads everything from the validated spec. resolvedRootfs is the
// block path the kernel must mount (the overlay) and is the single source of
// truth — the caller already created it. egressAddr, when non-empty, is the
// host:port of this task's dedicated egress listener; it is forwarded to the
// guest so the guest dials it as its HTTP proxy. The task id is deliberately
// NOT passed: the guest cannot be trusted with its own attribution id, and
// the per-task listener binds the id by closure on the host side instead.
func buildTaskArgs(s *spec.TaskSpec, vhostSock, resolvedRootfs, egressAddr string) []string {
	args := []string{
		fmt.Sprintf("init=%s", s.Workspace.Init),
		fmt.Sprintf("mem=%s", s.Runtime.Memory),
	}
	if s.Kernel.UseVhostBlk && vhostSock != "" {
		args = append(args, fmt.Sprintf("virtio_uml.device=%s:%d", vhostSock, vhost.VirtioIDBlock))
		args = append(args, "root=/dev/vda")
	} else {
		// ubd path: resolvedRootfs is the single source of truth that StartTask
		// provisioned. StartTask sets it whenever BaseImage != "", so reaching
		// here with it empty means BaseImage was empty too — there is nothing
		// valid to fall back to. Don't re-derive from Workspace.Overlay/
		// BaseImage: that would let an unprovisioned file onto the kernel
		// command line and break the "cmdline matches what we created"
		// invariant resolvedRootfs exists to enforce.
		args = append(args, fmt.Sprintf("ubd0=%s", resolvedRootfs))
		args = append(args, "root=/dev/ubda")
	}
	args = append(args, "rw")
	// Network device: vec0 (vector tap transport). Since Linux 6.16 the legacy
	// UML net transports (CONFIG_UML_NET + eth0=tuntap/slip/daemon/...) are
	// GONE — only CONFIG_UML_NET_VECTOR remains, so the kernel only parses
	// 'vecN:transport=...' parameters. 'eth0=tuntap,<tap>' is reported as an
	// unknown command-line parameter and the guest gets no NIC. The vec tap
	// transport requires the host tap to exist and be UP (the caller's job:
	// `ip tuntap add` + `ip link set up`) and root or CAP_NET_ADMIN.
	// Parameters per Documentation/virt/uml/user_mode_linux_howto_v2.rst:
	//   transport=tap, ifname=<host tap>, depth=128 (queue depth), gro=1.
	if s.Network.Enabled && s.Network.TAP != "" {
		args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,depth=128,gro=1", s.Network.TAP))
	}
	// Forward the task's DEDICATED egress listener address (host:port) into the
	// guest so it can dial it as its HTTP proxy. Attribution is established by
	// which listener the traffic arrives on (a host-side closure over taskID),
	// not by any id the guest could forge. See StartTask for the lifecycle.
	if egressAddr != "" {
		args = append(args, fmt.Sprintf("egress_proxy=%s", egressAddr))
	}
	return args
}

// idRegexp is the task id format used by StartTask's defense-in-depth check.
// Mirrors the regex used by state.ContainerDir / the CLI.
var idRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
