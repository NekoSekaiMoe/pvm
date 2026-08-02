package container

import (
	"context"
	"fmt"
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
	// Record the SPEC+VERSION evidence (plan.md §14.2 phase 02).
	if err := ledger.Append(audit.Record{
		Phase:    audit.PhaseSpec,
		Subject:  s.Caller,
		Action:   "taskspec",
		Params:   map[string]interface{}{"fingerprint": s.Fingerprint(), "version": s.Version},
		Decision: audit.DecisionAllow,
		Reason:   "taskspec loaded",
	}); err != nil {
		log.Default().Warnf("container: audit taskspec for %s: %v", taskID, err)
	}

	// Load/create lifecycle state and drive the FSM.
	st, _ := state.LoadState(taskID)
	if st == nil {
		st = &state.ContainerState{ID: taskID, Name: s.Runtime.Name, Tenant: s.Tenant, Caller: s.Caller, StartedAt: time.Now()}
	}
	st.Name = s.Runtime.Name
	st.Tenant = s.Tenant
	st.Caller = s.Caller
	st.SpecFP = s.Fingerprint()
	st.Status = state.StatusPending
	state.SaveState(taskID, st)

	// Provisioning: create overlay, start vhost daemon, set up network+policy.
	if err := st.Transition(state.StatusProvisioning, state.ActorController, "start task"); err != nil {
		return err
	}
	state.SaveState(taskID, st)

	// qcow2 overlay over the shared base image (plan.md §5.2).
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
	resolvedRootfs := overlayPath
	if s.Workspace.BaseImage != "" {
		if err := cow.CreateOverlay(ctx, s.Workspace.BaseImage, overlayPath, cow.FormatRaw); err != nil {
			// overlay creation needs qemu-img; degrade to the flat rootfs if
			// we can't do CoW (with an explicit audit record).
			if laErr := ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "overlay", Decision: audit.DecisionConstrain, Reason: "qcow2 overlay failed: " + err.Error()}); laErr != nil {
				log.Default().Warnf("container: audit overlay fallback for %s: %v", taskID, laErr)
			}
			overlayPath = s.Workspace.BaseImage // fall back to read-only base
			resolvedRootfs = s.Workspace.BaseImage
		}
	}

	// vhost-user-blk backend over the overlay.
	var sockPath string
	var vhostProc *os.Process
	if s.Kernel.UseVhostBlk && s.Workspace.BaseImage != "" {
		sock, daemonCmd, err := vhost.StartStorageDaemon(taskID, resolvedRootfs)
		if err != nil {
			_ = st.Transition(state.StatusFailed, state.ActorController, "vhost daemon failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: vhost: %w", err)
		}
		sockPath = sock
		vhostProc = daemonCmd.Process
		defer func() {
			if vhostProc != nil {
				vhostProc.Kill()
			}
		}()
	}

	// Egress gateway policy (plan.md §4). The gateway is shared across tasks;
	// we register this task's allowlist. The sandbox gets HTTP_PROXY pointing
	// at it via the init contract (env injection is the caller's job).
	if m.Egress != nil && s.Network.Enabled {
		pol := &egress.Policy{
			AllowDomains:   s.Network.EgressAllowDomains,
			BlockDomains:   s.Network.EgressBlockDomains,
			MaxRequestBody:  s.Network.MaxRequestBodyBytes,
		}
		m.Egress.SetPolicy(taskID, pol)
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
	// kernel command line matches what we actually provisioned.
	args := buildTaskArgs(s, sockPath, dir, resolvedRootfs, taskID)

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
		log.Default().Warnf("container: audit task:start for %s: %v", taskID, err)
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
	if cfg.NetworkTap != "" {
		if cfg.UseVirtio {
			args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,vnet=1", cfg.NetworkTap))
		} else {
			args = append(args, fmt.Sprintf("eth0=tuntap,%s", cfg.NetworkTap))
		}
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
// block path the kernel must mount (the overlay, or the base image on fallback)
// and is the single source of truth — the caller already created it. taskID
// is exposed to the guest so the egress proxy can attribute traffic via the
// X-Task-Id header; it MUST match the id used to register the egress policy.
func buildTaskArgs(s *spec.TaskSpec, vhostSock, dir, resolvedRootfs, taskID string) []string {
	args := []string{
		fmt.Sprintf("init=%s", s.Workspace.Init),
		fmt.Sprintf("mem=%s", s.Runtime.Memory),
	}
	if s.Kernel.UseVhostBlk && vhostSock != "" {
		args = append(args, fmt.Sprintf("virtio_uml.device=%s:%d", vhostSock, vhost.VirtioIDBlock))
		args = append(args, "root=/dev/vda")
	} else {
		root := resolvedRootfs
		if root == "" {
			root = s.Workspace.Overlay
			if root == "" {
				root = s.Workspace.BaseImage
			}
		}
		args = append(args, fmt.Sprintf("ubd0=%s", root))
		args = append(args, "root=/dev/ubda")
	}
	args = append(args, "rw")
	if s.Network.Enabled && s.Network.TAP != "" {
		if s.Kernel.Virtio {
			args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,vnet=1", s.Network.TAP))
		} else {
			args = append(args, fmt.Sprintf("eth0=tuntap,%s", s.Network.TAP))
		}
	}
	// Expose the EXTERNAL task id to the guest so the egress gateway can
	// attribute traffic via X-Task-Id. This must match the id used at
	// Egress.SetPolicy(taskID, ...), otherwise the gateway cannot find the
	// policy and denies all traffic.
	args = append(args, fmt.Sprintf("task_id=%s", taskID))
	return args
}

// idRegexp is the task id format used by StartTask's defense-in-depth check.
// Mirrors the regex used by state.ContainerDir / the CLI.
var idRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
