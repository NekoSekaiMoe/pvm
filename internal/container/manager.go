package container

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"uml-container/internal/audit"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/cow"
	"uml-container/internal/identity"
	"uml-container/internal/lifecycle"
	"uml-container/internal/log"
	"uml-container/internal/network/egress"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/uml"
	"uml-container/internal/vhost"
	"uml-container/internal/volume"
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
	Volumes         *volume.Manager
	Autopause       *lifecycle.Manager

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
	args, err := buildLegacyArgs(ctx, cfg)
	if err != nil {
		return err
	}

	var logFile *os.File
	if interactive, _ := ctx.Value(KeyInteractive).(bool); !interactive {
		e := setupConsoleFile(cfg.ID, &logFile)
		if e != nil {
			return e
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
	// Full spec validation BEFORE any resource is touched (plan.md §3):
	// the per-field checks below (mount paths, validateRootfs, TAP charset in
	// buildTaskArgs) are defense in depth, not the gate. A spec that fails
	// Validate must not open ledgers, persist state, or attach volumes.
	if err := s.Validate(); err != nil {
		return fmt.Errorf("container: invalid task spec: %w", err)
	}
	// Hoist the static kernel-command-line validations out of buildTaskArgs
	// so a hostile spec fails BEFORE provisioning creates anything to clean
	// up (attached volumes, qcow2 overlays, vhost daemons). The socket,
	// egress address, volume host paths and resolved rootfs only exist later
	// and stay validated at build time.
	if err := validateKernelField("init", s.Workspace.Init); err != nil {
		return err
	}
	// Runtime.Memory is an OPTIONAL spec field (spec.Validate checks it only
	// when set): validate only when non-empty, so an unset memory boots
	// without mem= instead of failing the whole task.
	if s.Runtime.Memory != "" {
		if err := validateMemory(s.Runtime.Memory); err != nil {
			return err
		}
	}
	if s.Network.Enabled && s.Network.TAP != "" {
		if err := validateKernelField("tap device", s.Network.TAP); err != nil {
			return err
		}
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
	// Persist the lifecycle config snapshot so API endpoints (/exec,
	// /tasks/:id/*) can honor auto_resume/idle policy without the spec file.
	st.IdleTimeout = s.Lifecycle.IdleTimeout
	st.AutoResume = s.Lifecycle.AutoResume
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

	// Volume attachments: for each spec.Volumes entry, attach via volume.Manager
	// and collect hostfs_volume args. RefCounts are tracked inside Manager.
	// A spec that references volumes without a configured volume Manager must
	// fail BEFORE any runtime resource is launched — silently dropping the
	// mounts would run the task with different storage than contracted.
	if m.Volumes == nil && len(s.Volumes) > 0 {
		_ = st.Transition(state.StatusFailed, state.ActorController, "volumes requested but no volume manager configured")
		state.SaveState(taskID, st)
		return fmt.Errorf("container: task %s requests %d volumes but no volume manager is configured", taskID, len(s.Volumes))
	}
	// Guest mount points are embedded verbatim into the kernel cmdline as
	// hostfs_volume=<host>:<guest>:<mode>; whitespace/":"/"," would corrupt
	// that parameter. spec.Validate already rejects them, but StartTask is a
	// public entry point and must not trust that its caller validated — the
	// same defense-in-depth rule the task id check above follows.
	for _, vm := range s.Volumes {
		if err := spec.ValidateMountPath(vm.Path); err != nil {
			_ = st.Transition(state.StatusFailed, state.ActorController, "invalid volume mount path: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: volume %q: %w", vm.Name, err)
		}
	}
	var volumeArgs []string
	var attachedVolumes []spec.VolumeMount
	if m.Volumes != nil && len(s.Volumes) > 0 {
		for _, vm := range s.Volumes {
			// Resolve the driver ONCE at the attach point: an empty Driver means
			// "first registered plugin" (mirrors Cube's "first entry" rule).
			// Recording the resolved name on the mount copy (vm is a copy of the
			// spec entry, so the spec itself is not mutated) lets the rollback
			// and cleanupVolumes paths below detach through the SAME driver the
			// volume was attached with, instead of re-deriving the default —
			// which could pick a different plugin if registrations changed
			// mid-task.
			if vm.Driver == "" {
				if regs := m.Volumes.Registered(); len(regs) > 0 {
					vm.Driver = regs[0]
				}
			}
			res, err := m.Volumes.Attach(ctx, &volume.AttachRequest{
				SandboxID: taskID,
				VolumeID:  vm.Name,
				Driver:    vm.Driver,
			})
			if err != nil {
				// Detach already-attached volumes through their recorded drivers
				// before failing.
				for _, av := range attachedVolumes {
					_ = m.Volumes.Detach(context.Background(), &volume.DetachRequest{SandboxID: taskID, VolumeID: av.Name, Driver: av.Driver})
				}
				_ = st.Transition(state.StatusFailed, state.ActorController, "volume attach failed: "+err.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: volume attach %q: %w", vm.Name, err)
			}
			attachedVolumes = append(attachedVolumes, vm)
			// hostfs_volume is only valid on the host; guest sees it as a virtiofs/hostfs mount
			// For UML we wire via extra kernel args (hostfs_volume=host:guest)
			// The plugin-returned host path is spliced in verbatim below, so it
			// must pass the SAME separator rules as the guest path above
			// (spec.ValidateMountPath): whitespace splits the kernel command
			// line and ':'/',' are field separators. Inline rollback: the loop
			// below detaches this volume (appended above) plus everything
			// attached so far, mirroring the attach-failure path
			// (cleanupVolumes is defined only after the loop, so it cannot be
			// reused here).
			if err := spec.ValidateMountPath(res.HostPath); err != nil {
				for _, av := range attachedVolumes {
					_ = m.Volumes.Detach(context.Background(), &volume.DetachRequest{SandboxID: taskID, VolumeID: av.Name, Driver: av.Driver})
				}
				_ = st.Transition(state.StatusFailed, state.ActorController, "invalid volume host path: "+err.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: volume attach %q: %w", vm.Name, err)
			}
			mode := "rw"
			if vm.ReadOnly {
				mode = "ro"
			}
			volumeArgs = append(volumeArgs, fmt.Sprintf("%s:%s:%s", res.HostPath, vm.Path, mode))
		}
	}
	cleanupVolumes := func() {
		// av.Driver was resolved at attach time (see the loop above); reuse
		// the recorded name rather than re-deriving the default plugin here.
		for _, av := range attachedVolumes {
			_ = m.Volumes.Detach(context.Background(), &volume.DetachRequest{SandboxID: taskID, VolumeID: av.Name, Driver: av.Driver})
		}
		attachedVolumes = nil
	}
	// resolvedRootfs is the single source of truth for the block device the
	// kernel mounts. It is forwarded into buildTaskArgs so the kernel command
	// line and the overlay we actually created cannot drift apart.
	resolvedRootfs := ""
	overlayCreated := false // true only when we created a qcow2 overlay (the compact path)
	if s.Workspace.BaseImage != "" {
		if s.Kernel.UseVhostBlk {
			// vhost path: wrap the qcow2 base in a per-task qcow2 overlay.
			// The backing path comes from caller-supplied spec content, so it
			// gets the SAME trusted-root + symlink-resolved validation as the
			// rootfs the kernel boots (validateRootfsContained): a base outside
			// the image roots — or a symlink escaping them — must never reach
			// CreateOverlay, which would open it read-only and bind it into the
			// overlay's backing chain. Boot/open exactly the resolved path.
			resolvedBase, verr := validateRootfsContained(s.Workspace.BaseImage)
			if verr != nil {
				cleanupVolumes()
				_ = ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "overlay", Decision: audit.DecisionDeny, Reason: "base image validation failed: " + verr.Error()})
				_ = st.Transition(state.StatusFailed, state.ActorController, "base image validation failed: "+verr.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: base image %q for %s failed trusted-root validation: %w", s.Workspace.BaseImage, taskID, verr)
			}
			resolvedRootfs = overlayPath
			if err := cow.CreateOverlay(ctx, resolvedBase, overlayPath); err != nil {
				cleanupVolumes()
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

	// A half-provisioned overlay must not outlive a failed launch: every
	// failure path between here and overlayCommitted = true below returns
	// before the task becomes authoritatively Running, and the stale qcow2
	// (plus its backing registration) would be mistaken for a real task
	// image by later snapshots/metadata walks.
	overlayCommitted := false
	defer func() {
		if overlayCreated && !overlayCommitted {
			if rmErr := os.Remove(overlayPath); rmErr != nil && !os.IsNotExist(rmErr) {
				fmt.Printf("Warning: remove half-provisioned overlay %s: %v\n", overlayPath, rmErr)
			}
		}
	}()

	// vhost-user-blk backend over the overlay.
	var sockPath string
	var vhostBackend io.Closer
	var egressAddr string // host:port of this task's dedicated egress listener
	if s.Kernel.UseVhostBlk && s.Workspace.BaseImage != "" {
		sock, backend, err := vhost.StartBlk(taskID, resolvedRootfs)
		if err != nil {
			cleanupVolumes()
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
		for _, r := range s.Network.EgressRules {
			host := r.Host
			if host == "" {
				host = r.SNI
			}
			if host == "" {
				continue
			}
			if r.Allow != nil && !*r.Allow {
				pol.BlockDomains = append(pol.BlockDomains, host)
			} else {
				pol.AllowDomains = append(pol.AllowDomains, host)
			}
			// Also wire the full L7 rule so the gateway can enforce method/path/scheme and inject credentials.
			var inj *egress.EgressInject
			if r.Inject != nil {
				inj = &egress.EgressInject{Header: r.Inject.Header, Format: r.Inject.Format, Secret: r.Inject.Secret}
			}
			pol.Rules = append(pol.Rules, egress.EgressRule{
				Name:   r.Name,
				Host:   r.Host,
				SNI:    r.SNI,
				Method: r.Method,
				Path:   r.Path,
				Scheme: r.Scheme,
				Port:   r.Port,
				Allow:  r.Allow,
				Inject: inj,
			})
		}
		m.Egress.SetPolicy(taskID, pol)
		if lp, err := m.Egress.ListenForTask(ctx, taskID); err == nil {
			defer lp.Close()
			egressAddr = lp.Addr()
		} else {
			cleanupVolumes()
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
			cleanupVolumes()
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
	args, err := buildTaskArgs(s, sockPath, resolvedRootfs, egressAddr, volumeArgs)
	if err != nil {
		cleanupVolumes()
		_ = st.Transition(state.StatusFailed, state.ActorController, "kernel args rejected: "+err.Error())
		state.SaveState(taskID, st)
		return err
	}

	defer func() {
		if m.Autopause != nil {
			m.Autopause.Disarm(taskID)
		}
	}()

	// Non-interactive (agent sandbox) => log to file under the task dir.
	// Fail closed: if the console log cannot be created, route guest output
	// to os.DevNull instead of letting the launcher fall back to the host's
	// os.Stdin/os.Stdout (which would leak guest output into the daemon's
	// terminal). Interactive mode (explicit KeyInteractive) is unchanged.
	var logFile *os.File
	if interactive, _ := ctx.Value(KeyInteractive).(bool); !interactive {
		if e := setupConsoleFile(taskID, &logFile); e != nil {
			cleanupVolumes()
			_ = st.Transition(state.StatusFailed, state.ActorController, "console log setup failed: "+e.Error())
			state.SaveState(taskID, st)
			return e
		}
	}
	if logFile != nil {
		defer logFile.Close()
	}

	// Ready: sandbox process about to start.
	_ = st.Transition(state.StatusReady, state.ActorController, "provisioned")
	state.SaveState(taskID, st)

	pid, p, err := m.Launcher.Start(ctx, s.Kernel.Path, args, logFile)
	st.PID = pid
	if err != nil {
		cleanupVolumes()
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
		// The process is already launched; a sandbox must never keep running
		// without its task:start authorization evidence. Terminate it, wait
		// for exit, and release the attached volumes before failing.
		if p != nil && p.Cmd != nil && p.Cmd.Process != nil {
			_ = p.Cmd.Process.Kill()
			_ = m.Launcher.Wait(p)
		}
		cleanupVolumes()
		return fmt.Errorf("container: audit task:start for %s: %w", taskID, err)
	}
	// The task is now authoritatively Running with its task:start evidence
	// on disk: the overlay is a live task artifact, not half-provisioned
	// state — the deferred removal above must leave it alone from here on.
	overlayCommitted = true

	if m.OnProvisioned != nil {
		m.OnProvisioned(taskID, pid, tokenStr)
	}

	// Arm AutoPause only after StatusRunning is persisted AND the task:start
	// audit evidence is on disk: an armed timer for a task that never became
	// authoritatively Running would pause (or interfere with) a failed launch.
	if m.Autopause != nil && s.Lifecycle.IdleTimeout != "" {
		if d, err := time.ParseDuration(s.Lifecycle.IdleTimeout); err == nil && d > 0 {
			m.Autopause.Arm(taskID, d)
		}
	}

	// Block until the kernel exits.
	waitErr := m.Launcher.Wait(p)

	cleanupVolumes()

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
		// Close the vhost backend explicitly so it is not holding the overlay
		// file open while we rename a rebuilt file over it. The deferred close
		// at the top of StartTask becomes a no-op once we nil vhostBackend
		// here. A close failure means the backend may still be holding the
		// overlay: compacting would race that handle and could rebuild a
		// half-flushed image, so SKIP compact, record the close failure as an
		// audit constrain event, and leave vhostBackend non-nil so the
		// deferred cleanup gets a chance to retry the close.
		if vhostBackend != nil {
			if cerr := vhostBackend.Close(); cerr != nil {
				fmt.Printf("Warning: vhost backend close for %s failed: %v (skipping overlay compaction)\n", taskID, cerr)
				rec := audit.Record{
					Phase:    audit.PhaseExec,
					Subject:  taskID,
					Action:   "overlay_compact",
					Decision: audit.DecisionConstrain,
					Reason:   "vhost backend close failed, compact skipped: " + cerr.Error(),
				}
				if aerr := ledger.Append(rec); aerr != nil {
					// Non-fatal (the task already exited), but never silent: the
					// audit trail must record that a record COULD NOT be appended.
					fmt.Printf("Warning: audit append overlay_compact(close-failed) for %s: %v\n", taskID, aerr)
				}
			} else {
				vhostBackend = nil
			}
		}
		if vhostBackend == nil {
			stats, cerr := cow.Compact(context.Background(), overlayPath)
			if cerr != nil {
				fmt.Printf("Warning: compact overlay for %s failed: %v\n", taskID, cerr)
				rec := audit.Record{
					Phase:    audit.PhaseExec,
					Subject:  taskID,
					Action:   "overlay_compact",
					Decision: audit.DecisionConstrain,
					Reason:   "compact failed: " + cerr.Error(),
				}
				if aerr := ledger.Append(rec); aerr != nil {
					fmt.Printf("Warning: audit append overlay_compact(failed) for %s: %v\n", taskID, aerr)
				}
			} else {
				fmt.Printf("Overlay compacted for %s: %d -> %d bytes (%d clusters copied, %d zeroed, %d dropped)\n",
					taskID, stats.BeforeBytes, stats.AfterBytes, stats.ClustersCopied, stats.ClustersZeroed, stats.ClustersDropped)
				rec := audit.Record{
					Phase:    audit.PhaseExec,
					Subject:  taskID,
					Action:   "overlay_compact",
					Decision: audit.DecisionAllow,
					Reason: fmt.Sprintf("overlay compacted: %d -> %d bytes",
						stats.BeforeBytes, stats.AfterBytes),
				}
				if aerr := ledger.Append(rec); aerr != nil {
					fmt.Printf("Warning: audit append overlay_compact(ok) for %s: %v\n", taskID, aerr)
				}
			}
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

// setupConsoleFile creates the console log for containerID into *dst.
// On success *dst is the open log file. On failure *dst is os.DevNull
// (fail closed): the launcher must never fall back to host stdio for a
// non-interactive sandbox just because its log file could not be created.
func setupConsoleFile(containerID string, dst **os.File) error {
	f, err := log.SetupConsoleLog(containerID)
	if err == nil {
		*dst = f
		return nil
	}
	null, nerr := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if nerr != nil {
		return fmt.Errorf("container: console log setup failed (%v) and %s unusable (%v)", err, os.DevNull, nerr)
	}
	log.Default().Warnf("console log unavailable for %s (%v); routing guest output to %s", containerID, err, os.DevNull)
	*dst = null
	return nil
}

// kernelFieldRe rejects characters that would break out of a single UML
// command-line field: whitespace splits arguments and commas separate
// options inside composite parameters (vec0=..., virtio_uml.device=...,
// hostfs_volume=...). Field VALUES must not contain either; the composite
// strings built by the arg functions themselves may use commas freely.
var kernelFieldRe = regexp.MustCompile(`^[^\s,]+$`)

// validateKernelField enforces the character-set contract on a value
// interpolated into the UML kernel command line.
func validateKernelField(name, val string) error {
	if val == "" {
		return fmt.Errorf("container: empty %q in kernel command line", name)
	}
	if !kernelFieldRe.MatchString(val) {
		return fmt.Errorf("container: %s %q contains whitespace or comma", name, val)
	}
	return nil
}

// validateRootfs additionally requires an absolute path with no '..'
// element, a RESOLVABLE target and a regular file. It returns the fully
// symlink-resolved path — callers must interpolate THAT into ubd0= so the
// kernel mounts exactly what was validated: validating one path while
// booting another leaves the symlink-swap window open.
func validateRootfs(val string) (string, error) {
	if err := validateKernelField("rootfs", val); err != nil {
		return "", err
	}
	if !filepath.IsAbs(val) {
		return "", fmt.Errorf("container: rootfs %q must be an absolute path", val)
	}
	// Reject '..' as a raw path element BEFORE cleaning: lexical dot-dot
	// traversal (even when it stays inside the tree) has no business on a
	// kernel command line.
	for _, part := range strings.Split(val, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("container: rootfs %q must not contain '..'", val)
		}
	}
	resolved, err := filepath.EvalSymlinks(val)
	if err != nil {
		return "", fmt.Errorf("container: rootfs %q cannot be resolved: %w", val, err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("container: stat rootfs %q: %w", resolved, err)
	}
	// A device node, socket, fifo or directory named like an image must not
	// reach ubd0= — only an approved regular image file may.
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("container: rootfs %q is not a regular image file (%s)", resolved, fi.Mode().Type())
	}
	return resolved, nil
}

// containerImageRoots returns the roots a daemon-side rootfs may live under:
// the image store, the CoW root and the container state root (overlays are
// created there by StartTask). Read at CALL time so tests (t.Setenv) and
// config changes take effect; PVM_IMAGE_ROOT accepts a colon-separated list
// for deployments with several image stores.
func containerImageRoots() []string {
	roots := []string{"/var/lib/uml-container/images"}
	if r := os.Getenv("PVM_IMAGE_ROOT"); r != "" {
		roots = append(roots, filepath.SplitList(r)...)
	}
	if r := os.Getenv("PVM_COW_ROOT"); r != "" {
		roots = append(roots, r)
	} else {
		roots = append(roots, "/var/lib/uml-container/cow")
	}
	if r := os.Getenv("PVM_STATE_ROOT"); r != "" {
		roots = append(roots, r)
	} else {
		roots = append(roots, "/var/lib/uml-container/containers")
	}
	return roots
}

// validateRootfsContained adds the daemon-side containment rule on top of
// validateRootfs: the resolved rootfs must sit inside one of the trusted
// image roots. TaskSpec content arrives via the API from callers the daemon
// does not fully trust, so unlike the legacy umlctl path (a local operator's
// explicit --rootfs, validated by validateRootfs alone) it may not name any
// arbitrary host file.
func validateRootfsContained(val string) (string, error) {
	resolved, err := validateRootfs(val)
	if err != nil {
		return "", err
	}
	for _, root := range containerImageRoots() {
		realRoot, rerr := filepath.EvalSymlinks(root)
		if rerr != nil {
			continue // a root that cannot be resolved cannot vouch for anything
		}
		if resolved == realRoot || strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("container: rootfs %q is outside the trusted image roots", resolved)
}

// validateMemory accepts only canonical numeric forms the UML kernel
// understands: plain bytes ("268435456") or a single k/m/g suffix
// ("256M"). Anything else (arithmetic expressions, unknown units) is
// rejected rather than passed through to the kernel cmdline.
var memoryRe = regexp.MustCompile(`^[0-9]+[kKmMgG]?$`)

func validateMemory(val string) error {
	if !memoryRe.MatchString(val) {
		return fmt.Errorf("container: memory %q is not a canonical size (want digits with optional k/m/g suffix)", val)
	}
	return nil
}

// buildLegacyArgs reproduces the original UML command-line for the umlctl path.
// Extracted from the pre-refactor Start() to keep behavior byte-identical
// (modulo validation of interpolated fields).
func buildLegacyArgs(ctx context.Context, cfg *config.ContainerConfig) ([]string, error) {
	if err := validateKernelField("init", cfg.Init); err != nil {
		return nil, err
	}
	if err := validateMemory(cfg.Memory); err != nil {
		return nil, err
	}
	args := []string{
		fmt.Sprintf("init=%s", cfg.Init),
		fmt.Sprintf("mem=%s", cfg.Memory),
	}
	if interactive, _ := ctx.Value(KeyInteractive).(bool); interactive {
		args = append(args, "con0=fd:0,fd:1")
		args = append(args, "con=null")
	}
	if cfg.UseVirtio && cfg.VhostUserSocket != "" {
		if err := validateKernelField("vhost-user socket", cfg.VhostUserSocket); err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("virtio_uml.device=%s:%d", cfg.VhostUserSocket, vhost.VirtioIDBlock))
		args = append(args, "root=/dev/vda")
	} else {
		// The legacy umlctl default is a RELATIVE "rootfs.img" in the
		// working directory, while validateRootfs requires absolute paths.
		// Resolve to absolute BEFORE validating — filepath.Abs also cleans
		// "./" noise; EvalSymlinks and the regular-file check still run
		// inside validateRootfs on the resolved value.
		abs, err := filepath.Abs(cfg.Rootfs)
		if err != nil {
			return nil, fmt.Errorf("container: rootfs %q cannot be made absolute: %w", cfg.Rootfs, err)
		}
		resolved, err := validateRootfs(abs)
		if err != nil {
			return nil, err
		}
		// Boot exactly the path that passed validation (symlinks resolved).
		args = append(args, fmt.Sprintf("ubd0=%s", resolved))
		args = append(args, "root=/dev/ubda")
	}
	args = append(args, "rw")
	// Network device: vec0 (see buildTaskArgs — legacy eth0=tuntap is gone in
	// Linux >= 6.16, only the vector transport remains).
	if cfg.NetworkTap != "" {
		if err := validateKernelField("tap device", cfg.NetworkTap); err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,depth=128,gro=1", cfg.NetworkTap))
	}
	vHost, hasVHost := ctx.Value(KeyVolumeHost).(string)
	vGuest, hasVGuest := ctx.Value(KeyVolumeGuest).(string)
	if hasVHost && hasVGuest {
		if err := validateKernelField("volume host path", vHost); err != nil {
			return nil, err
		}
		if err := validateKernelField("volume guest path", vGuest); err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("hostfs_volume=%s:%s", vHost, vGuest))
	}
	return args, nil
}

// buildTaskArgs builds the UML command-line from a TaskSpec. Mirrors the legacy
// path but reads everything from the validated spec. resolvedRootfs is the
// block path the kernel must mount (the overlay) and is the single source of
// truth — the caller already created it. egressAddr, when non-empty, is the
// host:port of this task's dedicated egress listener; it is forwarded to the
// guest so the guest dials it as its HTTP proxy. The task id is deliberately
// NOT passed: the guest cannot be trusted with its own attribution id, and
// the per-task listener binds the id by closure on the host side instead.
func buildTaskArgs(s *spec.TaskSpec, vhostSock, resolvedRootfs, egressAddr string, volumeArgs []string) ([]string, error) {
	if err := validateKernelField("init", s.Workspace.Init); err != nil {
		return nil, err
	}
	// Runtime.Memory and the rootfs are OPTIONAL spec fields (spec.Validate
	// checks each only when set): validate only when present and omit the
	// matching kernel arg when unset — an empty mem=/ubd0= would be a broken
	// kernel parameter, so nothing is appended for unset fields.
	if s.Runtime.Memory != "" {
		if err := validateMemory(s.Runtime.Memory); err != nil {
			return nil, err
		}
	}
	args := []string{
		fmt.Sprintf("init=%s", s.Workspace.Init),
	}
	if s.Runtime.Memory != "" {
		args = append(args, fmt.Sprintf("mem=%s", s.Runtime.Memory))
	}
	if s.Kernel.UseVhostBlk && vhostSock != "" {
		if err := validateKernelField("vhost-user socket", vhostSock); err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("virtio_uml.device=%s:%d", vhostSock, vhost.VirtioIDBlock))
		args = append(args, "root=/dev/vda")
	} else if resolvedRootfs != "" {
		resolved, err := validateRootfsContained(resolvedRootfs)
		if err != nil {
			return nil, err
		}
		// Boot exactly the validated (resolved, contained) path.
		args = append(args, fmt.Sprintf("ubd0=%s", resolved))
		args = append(args, "root=/dev/ubda")
	}
	// resolvedRootfs empty: no block device was provisioned (BaseImage
	// unset), so the kernel boots init-only with no ubd0=/root= args.
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
		if err := validateKernelField("tap device", s.Network.TAP); err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,depth=128,gro=1", s.Network.TAP))
	}
	// Forward the task's DEDICATED egress listener address (host:port) into the
	// guest so it can dial it as its HTTP proxy. Attribution is established by
	// which listener the traffic arrives on (a host-side closure over taskID),
	// not by any id the guest could forge. See StartTask for the lifecycle.
	if egressAddr != "" {
		if err := validateKernelField("egress proxy", egressAddr); err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("egress_proxy=%s", egressAddr))
	}
	for _, v := range volumeArgs {
		// v is a composite "<host>:<guest>" pair produced by the volume
		// plane; each side must be comma/whitespace free (the ':' separator
		// and the commas of the hostfs_volume= grammar itself are fine).
		host, guest, found := strings.Cut(v, ":")
		if !found {
			return nil, fmt.Errorf("container: volume arg %q is not <host>:<guest>", v)
		}
		if err := validateKernelField("volume host path", host); err != nil {
			return nil, err
		}
		if err := validateKernelField("volume guest path", guest); err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("hostfs_volume=%s", v))
	}
	return args, nil
}

// idRegexp is the task id format used by StartTask's defense-in-depth check.
// Mirrors the regex used by state.ContainerDir / the CLI.
var idRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
