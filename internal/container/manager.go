package container

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"uml-container/internal/audit"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/console"
	"uml-container/internal/cow"
	"uml-container/internal/fsjson"
	"uml-container/internal/identity"
	"uml-container/internal/jail"
	"uml-container/internal/lifecycle"
	"uml-container/internal/log"
	"uml-container/internal/logx"
	"uml-container/internal/network"
	"uml-container/internal/network/dnslearn"
	"uml-container/internal/network/egress"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/uidalloc"
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

	// UIDTable is the centralized host-uid-range allocation table backing the
	// rootless hard boundary (internal/uidalloc; TODO.md "[P1] Jail rootless
	// 化"). Always non-nil from NewManager; allocation is only attempted on
	// privileged launches (the unprivileged leg maps the caller's own uid
	// with size 1 and needs no table).
	UIDTable *uidalloc.Table
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
	// Open never fails for a non-empty path (the file is created lazily);
	// allocation failures surface at Allocate time.
	tbl, _ := uidalloc.Open(uidalloc.DefaultPath())
	return &Manager{Launcher: launcher, UIDTable: tbl}
}

// uidRangeFor returns the container's allocated host uid range for the
// rootless hard boundary. (0, 0, nil) for unprivileged callers: their
// rootless leg maps the caller's own uid with size 1 and needs no
// allocation. A privileged caller gets an idempotent allocation from the
// centralized table (start allocates, stop releases — WaitExit/StartTask);
// an error means the table is unusable and the caller must choose between
// fail-closed and degraded (security.allow_insecure_degraded).
func (m *Manager) uidRangeFor(id string) (uint32, uint32, error) {
	if os.Geteuid() != 0 || m.UIDTable == nil {
		return 0, 0, nil
	}
	base, err := m.UIDTable.Allocate(id)
	if err != nil {
		return 0, 0, err
	}
	return base, uidalloc.RangeSize, nil
}

// releaseUIDRange frees the container's uid slot at stop time. Releasing an
// id that was never allocated is a no-op, so cleanup paths call it
// unconditionally.
func (m *Manager) releaseUIDRange(id string) {
	if m.UIDTable == nil || os.Geteuid() != 0 {
		return
	}
	if err := m.UIDTable.Release(id); err != nil {
		fmt.Printf("Warning: release uid range for %s: %v\n", id, err)
	}
}

// rootlessJailActive reports whether the upcoming launch will actually put
// the monitor under NEWUSER+NEWPID (mirrors the predicate
// ConfigureProcessIsolation applies): privileged caller, usable user+mount
// namespaces, and an allocated uid range.
func rootlessJailActive(uidRange uint32) bool {
	if uidRange == 0 || os.Geteuid() != 0 {
		return false
	}
	caps := jail.DetectHostCapabilities()
	return caps.HasUserNS && caps.HasMountNS
}

// prepareTapFD performs the host-side privileged half of tap setup for a
// rootless launch: open /dev/net/tun + TUNSETIFF + offload/vnet-header
// programming (network.OpenTapFD), returning the fd to inherit into the
// jail as ExtraFiles slot 0 — fd 3 in the workload (os/exec contract).
// (nil, -1, nil) selects the legacy vec0:transport=tap path: no tap
// configured, or a non-rootless launch where the (real-root) monitor can
// still TUNSETIFF for itself. Fail-closed when a rootless launch cannot
// attach: the namespaced monitor has no CAP_NET_ADMIN fallback.
func prepareTapFD(tapName string, rootless bool) (*os.File, int, error) {
	if tapName == "" || !rootless {
		return nil, -1, nil
	}
	f, err := network.OpenTapFD(tapName)
	if err != nil {
		return nil, -1, fmt.Errorf("container: rootless tap attach for %s: %w", tapName, err)
	}
	return f, 3, nil
}

// Booted is a started legacy container: the process handle plus the jail
// environment that must OUTLIVE it (the kernel pivot_roots into the jail
// directory, so Cleanup may only run after the process exits — see WaitExit).
type Booted struct {
	Process *uml.Process
	jail    *jail.JailEnvironment
	// logFile is the console log created during Boot (nil in interactive
	// mode). The launcher only writes to it via copy goroutines drained by
	// Wait; ownership of closing it stays with WaitExit / Boot error paths.
	logFile io.WriteCloser
	// consoleOut/consoleErr are the rotating per-stream logs; closed with
	// logFile in WaitExit / Boot error paths.
	consoleOut io.WriteCloser
	consoleErr io.WriteCloser
}

// closeConsoleLogs closes every console writer (idempotent, nil-safe).
func (b *Booted) closeConsoleLogs() {
	if b.logFile != nil {
		_ = b.logFile.Close()
		b.logFile = nil
	}
	if b.consoleOut != nil {
		_ = b.consoleOut.Close()
		b.consoleOut = nil
	}
	if b.consoleErr != nil {
		_ = b.consoleErr.Close()
		b.consoleErr = nil
	}
}

// closeWriters is the free-function form for Boot's error paths (before a
// Booted exists).
func closeWriters(ws ...io.WriteCloser) {
	for _, w := range ws {
		if w != nil {
			_ = w.Close()
		}
	}
}

// Start is the legacy entry point used by umlctl. It boots a UML kernel with
// the given flat config, sets up cgroup limits, and records legacy status
// (running/stopped/exited) in state.json. It does NOT engage the control planes.
// Start blocks until the UML process exits; callers that must report "started"
// immediately use Boot + WaitExit instead.
func (m *Manager) Start(ctx context.Context, cfg *config.ContainerConfig) error {
	b, err := m.Boot(ctx, cfg)
	if err != nil {
		return err
	}
	return m.WaitExit(cfg.ID, b)
}

// Boot performs everything Start does up to and including Launcher.Start,
// cgroup setup, and the Running state transition, then RETURNS as soon as
// the process has started. The caller MUST eventually call WaitExit to reap
// the process, record the terminal status, and release the jail directory.
func (m *Manager) Boot(ctx context.Context, cfg *config.ContainerConfig) (*Booted, error) {
	// Rootless hard boundary plumbing, BEFORE args are built: the uid range
	// decides both the jail mapping and whether the tap is attached
	// host-side and inherited as an fd (vec0:transport=fd) instead of being
	// TUNSETIFF'd at runtime by the monitor — namespaced root holds no
	// CAP_NET_ADMIN in the host netns (TODO.md "[P1] Jail rootless 化").
	uidBase, uidRange, err := m.uidRangeFor(cfg.ID)
	if err != nil {
		if !cfg.AllowInsecureDegraded {
			return nil, fmt.Errorf("container: allocate uid range for %s: %w (set security.allow_insecure_degraded to run with the degraded mountns-only jail)", cfg.ID, err)
		}
		fmt.Printf("Warning: uid range allocation for %s failed (%v); running with degraded mountns-only jail\n", cfg.ID, err)
		uidBase, uidRange = 0, 0
	}
	booted := false
	defer func() {
		if !booted {
			m.releaseUIDRange(cfg.ID)
		}
	}()

	tapFile, tapFD, err := prepareTapFD(cfg.NetworkTap, rootlessJailActive(uidRange))
	if err != nil {
		return nil, err
	}
	if tapFile != nil {
		// The workload inherits its own copy via ExtraFiles; the manager's
		// copy is closed when Boot returns, success or failure.
		defer tapFile.Close()
	}

	args, err := buildLegacyArgs(ctx, cfg, tapFD)
	if err != nil {
		return nil, err
	}

	var logFile io.WriteCloser
	var consoleOut, consoleErr io.WriteCloser
	if interactive, _ := ctx.Value(KeyInteractive).(bool); !interactive {
		lf, outW, errW, e := setupConsoleWriters(cfg.ID)
		if e != nil {
			return nil, e
		}
		logFile, consoleOut, consoleErr = lf, outW, errW
		// Per-stream rotating logs (console.out.log / console.err.log) ride
		// alongside the combined console.log.
		ctx = context.WithValue(ctx, uml.KeyStdoutWriter, consoleOut)
		ctx = context.WithValue(ctx, uml.KeyStderrWriter, consoleErr)
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

	secRep, secErr := jail.CheckSecurity(cfg.AllowInsecureDegraded, true, true)
	if secErr != nil {
		closeWriters(logFile, consoleOut, consoleErr)
		st.Status = state.StatusExited
		state.SaveState(cfg.ID, st)
		return nil, secErr
	}
	_ = secRep

	// A SetupJail failure must abort the boot BEFORE Launcher.Start:
	// continuing without the jail environment would run the kernel
	// un-isolated while the state file claims the task started normally.
	// Same status-save-then-return shape as the secErr branch above.
	jailEnv, jailErr := jail.SetupJail(jail.Config{
		TaskID:                cfg.ID,
		AllowInsecureDegraded: cfg.AllowInsecureDegraded,
		EnforceHostSeccomp:    true,
		EnforceLandlock:       true,
		UIDBase:               uidBase,
		UIDRangeSize:          uidRange,
	})
	if jailErr != nil {
		closeWriters(logFile, consoleOut, consoleErr)
		st.Status = state.StatusExited
		state.SaveState(cfg.ID, st)
		return nil, jailErr
	}
	if jailEnv != nil {
		if jailEnv.IsolationActive() {
			// The kernel will pivot_root into the jail: rewrite every host
			// path on its command line (ubd image, vhost socket, hostfs
			// volumes) to the in-jail bind mount and make the tap device
			// node visible. With the fd transport (tapFD >= 0) the tap is
			// already attached host-side and inherited, so /dev/net/tun is
			// NOT bound into the jail at all.
			tapName := cfg.NetworkTap
			if tapFD >= 0 {
				tapName = ""
			}
			var vols []jail.VolumeMapping
			args, vols = routeLaunchThroughJail(args, tapName)
			jailEnv.Config.Volumes = vols
			grantMonitorImageAccess(jailEnv, vols, uidBase)
		}
		if tapFile != nil {
			ctx = context.WithValue(ctx, uml.KeyExtraFiles, []*os.File{tapFile})
		}
		ctx = context.WithValue(ctx, uml.KeyJailEnv, jailEnv)
	}

	// Console session: capture guest output into a ring buffer (for exec,
	// PTY and /console tail) and give the launcher a stdin pipe handle so
	// the host can drive the guest shell with marker scripts.
	var consoleSession *console.Session
	if logFile != nil {
		consoleSession = console.Default().Attach(cfg.ID)
		ctx = context.WithValue(ctx, uml.KeyConsoleTee, consoleSession)
	}
	pid, p, err := m.Launcher.Start(ctx, cfg.Kernel, args, logFile)
	// Stamp the pid WITH its /proc starttime: later control paths
	// (deep pause checkpoint+kill) refuse to act on a recycled pid.
	state.StampPID(st, pid)
	if err != nil {
		if consoleSession != nil {
			console.Default().Detach(cfg.ID)
		}
		closeWriters(logFile, consoleOut, consoleErr)
		// The process never started, so nothing pivot_rooted into the jail:
		// release it here (on success WaitExit owns the cleanup).
		if jailEnv != nil {
			_ = jailEnv.Cleanup()
		}
		st.Status = state.StatusExited
		state.SaveState(cfg.ID, st)
		return nil, err
	}

	cg := cgroup.NewManager()
	if setupErr := cg.Setup(cfg.ID, pid, cfg.MemoryBytes, cfg.CPU); setupErr != nil {
		// Fail closed when limits were REQUESTED: releasing stage 1 now
		// would run the whole workload tree WITHOUT the intended CPU/memory
		// limits. Never SignalReady — kill the barrier-blocked stage-1
		// child, reap it, then report the launch as failed (the jail
		// cleanup closes the sync pipe, so the child would see EOF and
		// abort even without the kill).
		// Without requested limits a cgroup failure stays a warning: no
		// intended limit is being dropped (cgroup-less test/CI hosts).
		if cfg.MemoryBytes > 0 || cfg.CPU > 0 {
			if p != nil && p.Cmd != nil && p.Cmd.Process != nil {
				_ = p.Cmd.Process.Kill()
				_ = m.Launcher.Wait(p)
			}
			if consoleSession != nil {
				console.Default().Detach(cfg.ID)
			}
			if jailEnv != nil {
				_ = jailEnv.Cleanup()
			}
			closeWriters(logFile, consoleOut, consoleErr)
			st.Status = state.StatusExited
			state.SaveState(cfg.ID, st)
			return nil, fmt.Errorf(
				"container: cgroup setup for %s with requested limits: %w",
				cfg.ID, setupErr,
			)
		}
		fmt.Printf("Warning: failed to setup cgroup limits for %s: %v\n", cfg.ID, setupErr)
	}
	// Unblock stage 1 only AFTER cgroup membership covers the stage-1 pid:
	// stage 2 is forked after this point and inherits the cgroup, so the
	// whole workload tree is inside the limits.
	if jailEnv != nil {
		jailEnv.SignalReady()
	}

	st.Status = state.StatusRunning
	state.SaveState(cfg.ID, st)

	if m.OnProvisioned != nil {
		m.OnProvisioned(cfg.ID, pid, "")
	}

	if consoleSession != nil && p.Stdin != nil {
		consoleSession.SetStdin(p.Stdin)
	}
	booted = true
	return &Booted{Process: p, jail: jailEnv, logFile: logFile, consoleOut: consoleOut, consoleErr: consoleErr}, nil
}

// WaitExit blocks until a Booted process exits, records the terminal legacy
// status, and releases the jail directory (which the running kernel used as
// its pivot_root target, so it cannot be removed earlier). It returns the
// process wait error. When the state directory is gone (e.g. the create
// path tore the sandbox down), the terminal status is skipped rather than
// recreating a phantom state.json.
func (m *Manager) WaitExit(id string, b *Booted) error {
	if b.jail != nil {
		defer b.jail.Cleanup()
	}
	// Start allocates the container's host uid range, stop releases it.
	defer m.releaseUIDRange(id)
	// The console session dies with the guest: wake every tail/exec waiter.
	defer console.Default().Detach(id)
	err := m.Launcher.Wait(b.Process)
	// Wait drained the log-copy goroutines; the console log set can be
	// closed now that the process lifecycle is complete.
	b.closeConsoleLogs()
	st, lerr := state.LoadState(id)
	if lerr == nil && st != nil {
		// Deep pause: the process death was INTENTIONAL (checkpointed and
		// killed by lifecycle.DeepPause); the Suspended state must survive
		// for the criu-restore resume — do not record a terminal status.
		if st.Status == state.StatusSuspended && st.Metadata["pause_mode"] == "deep" {
			return err
		}
		if err != nil {
			st.Status = state.StatusExited
		} else {
			st.Status = state.StatusStopped
		}
		state.SaveState(id, st)
	}
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
	// Defense in depth: validate taskID BEFORE it reaches the filesystem
	// (audit.Open and state.ContainerDir both join taskID into host paths).
	// The caller (agentpvm) already enforces this, but StartTask is a public
	// entry point and must not trust its input for path derivation.
	if !idRegexp.MatchString(taskID) {
		return fmt.Errorf("container: invalid task id %q (must match %s)", taskID, idRegexp.String())
	}
	// Full spec validation BEFORE any resource is touched (plan.md §3):
	// the per-field checks below (mount paths, validateRootfs, TAP charset in
	// buildTaskArgs) are defense in depth, not the gate. A spec that fails
	// Validate must not even be persisted — no spec.json on disk, no opened
	// ledgers, no state, no attached volumes.
	if err := s.Validate(); err != nil {
		return fmt.Errorf("container: invalid task spec: %w", err)
	}
	// Persist the canonical (already validated) spec next to the state: the
	// artifact gate, TTL watchdog and other control planes re-read it
	// (spec.json, atomic write). A task whose spec cannot be persisted must
	// not start — those planes would silently run in legacy no-spec mode
	// (no TTL, no budget, no gate).
	specDir, derr := state.ContainerDir(taskID)
	if derr != nil {
		return fmt.Errorf("container: resolve task dir: %w", derr)
	}
	if mkerr := os.MkdirAll(specDir, 0o700); mkerr != nil {
		return fmt.Errorf("container: create task dir: %w", mkerr)
	}
	if werr := fsjson.Write(filepath.Join(specDir, "spec.json"), s); werr != nil {
		return fmt.Errorf("container: persist task spec: %w", werr)
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

	// Security Baseline & Fail-Closed Gate:
	secRep, secErr := jail.CheckSecurity(s.Security.AllowInsecureDegraded, s.Security.EnforceHostSeccomp, s.Security.EnforceLandlock)
	if secErr != nil {
		_ = st.Transition(state.StatusFailed, state.ActorController, "security check failed: "+secErr.Error())
		state.SaveState(taskID, st)
		return secErr
	}
	if secRep != nil && secRep.Degraded {
		// The degraded warning is the ONLY auditable trace that this task ran
		// below the full security baseline. Silently dropping a failed append
		// would let a downgraded sandbox boot with no evidence of the
		// downgrade, so fail closed (Failed transition + no Provisioning),
		// matching the spec-evidence append above.
		if err := ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  s.Caller,
			Action:   "security:degraded_warning",
			Decision: audit.DecisionAllow,
			Reason:   secRep.Details,
		}); err != nil {
			_ = st.Transition(state.StatusFailed, state.ActorController, "audit degraded-warning append failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: audit degraded warning for %s: %w", taskID, err)
		}
	}

	// Rootless hard boundary (TODO.md "[P1] Jail rootless 化"): allocate the
	// task's dedicated 65536-wide host uid range. The range is released when
	// StartTask returns (start allocates, stop releases); crashes leak a slot
	// that uidalloc.Prune can reclaim later.
	uidBase, uidRange, err := m.uidRangeFor(taskID)
	if err != nil {
		if !s.Security.AllowInsecureDegraded {
			_ = st.Transition(state.StatusFailed, state.ActorController, "uid range allocation failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: allocate uid range for %s: %w", taskID, err)
		}
		// Same audit contract as the CheckSecurity degraded warning above:
		// a downgraded sandbox must never boot without an auditable trace.
		if aerr := ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  s.Caller,
			Action:   "security:degraded_warning",
			Decision: audit.DecisionAllow,
			Reason:   "uid range allocation failed, running with degraded mountns-only jail: " + err.Error(),
		}); aerr != nil {
			_ = st.Transition(state.StatusFailed, state.ActorController, "audit degraded-warning append failed: "+aerr.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: audit degraded warning for %s: %w", taskID, aerr)
		}
		uidBase, uidRange = 0, 0
	}
	defer m.releaseUIDRange(taskID)

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
			// "first registered plugin" (the registry order decides the default).
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
				HostPath:  vm.HostPath,
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
			// Rootless jail ownership preflight (see volumeAccessNote): when
			// the monitor will run under NEWUSER, foreign-owned volumes that
			// are not world-accessible will EACCES in the guest. Warn with an
			// audit record instead of failing — the top-level check is a
			// heuristic and subdirectories may still be fine. An audit-append
			// failure is non-fatal (the task contract is unchanged), matching
			// the other warning-level audit sites below.
			if note := volumeAccessNote(res.HostPath, uidBase, uidRange, vm.ReadOnly); note != "" {
				fmt.Printf("Warning: volume %q for %s: %s\n", vm.Name, taskID, note)
				if aerr := ledger.Append(audit.Record{
					Phase: audit.PhaseExec, Subject: taskID, Action: "volume_access",
					Decision: audit.DecisionConstrain, Reason: note,
				}); aerr != nil {
					fmt.Printf("Warning: audit append volume_access for %s: %v\n", taskID, aerr)
				}
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
			if s.Workspace.Ephemeral {
				// Ephemeral: serve the base READ-ONLY directly — no overlay is
				// created, so no guest write can ever reach the host disk. This
				// is belt-and-suspenders with the kernel cmdline "ro": a
				// malicious guest init that remounts the root rw still hits a
				// read-only block device (VIRTIO_BLK_F_RO) and an O_RDONLY fd.
				resolvedRootfs = resolvedBase
				_ = ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "rootfs", Decision: audit.DecisionConstrain, Reason: "ephemeral mode: base image served read-only (no qcow2 overlay)"})
			} else {
				if err := cow.CreateOverlay(ctx, resolvedBase, overlayPath); err != nil {
					cleanupVolumes()
					_ = ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "overlay", Decision: audit.DecisionDeny, Reason: "qcow2 overlay failed: " + err.Error()})
					_ = st.Transition(state.StatusFailed, state.ActorController, "overlay creation failed: "+err.Error())
					state.SaveState(taskID, st)
					return fmt.Errorf("container: create qcow2 overlay for %s: %w", taskID, err)
				}
				// The overlay is opened by the vhost backend (manager-side) and,
				// on ubd paths, potentially by the namespaced monitor: ownership
				// must land inside the container's uid range so DAC passes once
				// the monitor is mere namespaced root.
				if uidRange > 0 {
					if chErr := os.Chown(overlayPath, int(uidBase), int(uidBase)); chErr != nil {
						cleanupVolumes()
						_ = st.Transition(state.StatusFailed, state.ActorController, "overlay chown failed: "+chErr.Error())
						state.SaveState(taskID, st)
						return fmt.Errorf("container: chown overlay %s into uid range %d: %w", overlayPath, uidBase, chErr)
					}
				}
				overlayCreated = true
			}
		} else {
			// ubd path: mount the base directly (no CoW). Works with raw or
			// qcow2-as-flat-file; ubd reads raw bytes, so callers normally pass
			// a raw ext4 image here. Recorded as a constrained isolation level.
			resolvedRootfs = s.Workspace.BaseImage
			if s.Workspace.Ephemeral {
				// Ephemeral on the ubd path: buildTaskArgs appends the ubd 'r'
				// flag (ubd0r=), so the device itself is opened read-only on
				// the host — device-level enforcement on par with the vhost
				// path's read-only backend, on top of the cmdline "ro".
				_ = ledger.Append(audit.Record{
					Phase: audit.PhaseExec, Subject: taskID, Action: "rootfs",
					Decision: audit.DecisionConstrain,
					Reason:   "ephemeral mode: ubd0r boots the base device-read-only (no qcow2 CoW)",
				})
			} else {
				_ = ledger.Append(audit.Record{Phase: audit.PhaseExec, Subject: taskID, Action: "rootfs", Decision: audit.DecisionConstrain, Reason: "ubd backend mounts base directly (no qcow2 CoW)"})
			}
		}
	}

	// A half-provisioned overlay must not outlive a failed launch: every
	// failure path between here and overlayCommitted = true below returns
	// before the task becomes authoritatively Running, and the stale qcow2
	// (plus its backing registration) would be mistaken for a real task
	// image by later snapshots/metadata walks. cow.RemoveOverlay (not a bare
	// os.Remove) also drops the backing-root registration CreateOverlay
	// recorded for this overlay; it tolerates a missing overlay file itself.
	overlayCommitted := false
	defer func() {
		if overlayCreated && !overlayCommitted {
			if rmErr := cow.RemoveOverlay(overlayPath); rmErr != nil {
				fmt.Printf("Warning: remove half-provisioned overlay %s: %v\n", overlayPath, rmErr)
			}
		}
	}()

	// vhost-user-blk backend over the overlay.
	var sockPath string
	var vhostBackend io.Closer
	var egressAddr string // host:port of this task's dedicated egress listener
	// rawEgressAddr is the listener's real bound address before the tc
	// dataplane rewrites it to the fixed gateway; the bridge fallback
	// (tc attach failure + bridge configured) restores it so the guest
	// dials exactly what bridge mode would have injected.
	var rawEgressAddr string
	if s.Kernel.UseVhostBlk && s.Workspace.BaseImage != "" {
		var sock string
		var backend io.Closer
		var err error
		if s.Workspace.Ephemeral {
			// Ephemeral sandboxes serve the base image through a read-only
			// backend (VIRTIO_BLK_F_RO + O_RDONLY fd) instead of a writable
			// overlay — see the provisioning block above.
			sock, backend, err = vhost.StartBlkReadOnly(taskID, resolvedRootfs)
		} else {
			sock, backend, err = vhost.StartBlk(taskID, resolvedRootfs)
		}
		if err != nil {
			cleanupVolumes()
			_ = st.Transition(state.StatusFailed, state.ActorController, "vhost daemon failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: vhost: %w", err)
		}
		sockPath = sock
		vhostBackend = backend
		// The namespaced monitor connects to the vhost socket through an
		// in-jail bind of the HOST path: it must be able to traverse the
		// state dir (o+x, no list) and write the socket inode (connect
		// permission). The state dir contents stay root-owned; only
		// traversal is granted.
		if uidRange > 0 {
			if err := os.Chmod(dir, 0711); err != nil {
				cleanupVolumes()
				_ = st.Transition(state.StatusFailed, state.ActorController, "vhost state dir chmod failed: "+err.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: chmod vhost state dir %s for monitor traversal: %w", dir, err)
			}
			if chErr := os.Chown(sockPath, int(uidBase), int(uidBase)); chErr != nil {
				cleanupVolumes()
				_ = st.Transition(state.StatusFailed, state.ActorController, "vhost socket chown failed: "+chErr.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: chown vhost socket %s into uid range %d: %w", sockPath, uidBase, chErr)
			}
		}
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
	//
	// P2 (tc dataplane): the guest's proxy target is the FIXED link-local
	// gateway 169.254.68.5 — identical inside every sandbox. The per-task
	// listener then binds that address on the shared pvm-gw dummy device and
	// the tap_ingress TC program redirects gateway-destined frames into the
	// host stack via pvm-gw. When pvm-gw cannot be set up (no
	// root/CAP_NET_ADMIN) or the bind fails, we degrade with an audit
	// warning and STILL inject the fixed address: fail-closed (unreachable)
	// beats silently telling the guest an address that happens to work.
	// dataplane "auto" resolves BEFORE anything else touches the network:
	// port mappings pin bridge (static inbound DNAT), L7-rule tasks pin
	// bridge (transparent interception is iptables-side), and a non-root
	// process cannot load eBPF anyway. Otherwise tc is preferred for its
	// no-iptables posture; its attach path already degrades back to bridge
	// when a bridge/gateway is configured.
	if s.Network.Enabled && s.Network.Dataplane == spec.DataplaneAuto {
		resolved := resolveAutoDataplane(s)
		s.Network.Dataplane = resolved
		_ = ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  s.Caller,
			Action:   "network:dataplane_auto",
			Params:   map[string]interface{}{"resolved": resolved},
			Decision: audit.DecisionAllow,
			Reason:   "dataplane auto-selection",
		})
	}
	tcDataplane := s.Network.Enabled && s.Network.Dataplane == spec.DataplaneTC
	// Transparent L7 bookkeeping (bridge plane): the wildcard listener's
	// port (0 = none) and the guest IP whose :80/:443 REDIRECT rules must
	// be removed at teardown.
	transparentPort := 0
	transparentGuestIP := ""
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
				inj = &egress.EgressInject{Header: r.Inject.Header, Format: r.Inject.Format, Secret: r.Inject.Secret, AllowPlainHTTP: r.Inject.AllowPlainHTTP}
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
				MITM:   r.MITM,
			})
		}
		m.Egress.SetPolicy(taskID, pol)
		// Transparent L7 interception (bridge plane only): when a policy is
		// declared, a second per-task listener accepts iptables-REDIRECTed
		// :80/:443 traffic so the guest needs NO proxy configuration. The
		// REDIRECT rules are installed later, once the guest IP exists.
		hasL7Policy := len(s.Network.EgressRules) > 0 ||
			len(s.Network.EgressAllowDomains) > 0 ||
			len(s.Network.EgressBlockDomains) > 0
		if hasL7Policy && !tcDataplane {
			if tln, terr := m.Egress.ListenTransparentForTask(ctx, taskID); terr == nil {
				defer tln.Close()
				if _, port, perr := net.SplitHostPort(tln.Addr()); perr == nil {
					if pv, convErr := strconv.Atoi(port); convErr == nil {
						transparentPort = pv
					}
				}
			} else {
				warn := fmt.Sprintf("transparent L7 listener bind failed: %v; egress enforcement stays explicit-proxy", terr)
				fmt.Printf("Warning: %s\n", warn)
				if aerr := appendDegradedWarning(ledger, s.Caller, warn); aerr != nil {
					cleanupVolumes()
					_ = st.Transition(state.StatusFailed, state.ActorController, "audit transparent-l7 degraded-warning append failed: "+aerr.Error())
					state.SaveState(taskID, st)
					return fmt.Errorf("container: audit transparent-l7 degraded warning for %s: %w", taskID, aerr)
				}
			}
		}
		listenAddr := ""
		if tcDataplane {
			if _, gwErr := network.EnsureGwDevice(); gwErr != nil {
				warn := fmt.Sprintf("tc dataplane pvm-gw setup failed: %v; "+
					"egress listener falls back to loopback (proxy UNREACHABLE from the guest)", gwErr)
				fmt.Printf("Warning: %s\n", warn)
				if aerr := appendDegradedWarning(ledger, s.Caller, warn); aerr != nil {
					cleanupVolumes()
					_ = st.Transition(state.StatusFailed, state.ActorController, "audit pvm-gw degraded-warning append failed: "+aerr.Error())
					state.SaveState(taskID, st)
					return fmt.Errorf("container: audit pvm-gw degraded warning for %s: %w", taskID, aerr)
				}
			} else {
				listenAddr = net.JoinHostPort(network.TapDataplaneGatewayIP, "0")
			}
		}
		lp, err := m.Egress.ListenForTaskOn(ctx, taskID, listenAddr)
		if err != nil && listenAddr != "" {
			// The gateway address existed moments ago but cannot be bound
			// (race with another teardown, port pressure): degrade to
			// loopback with evidence, same fail-closed injection below.
			warn := fmt.Sprintf("tc dataplane egress listener bind %s failed: %v; "+
				"falling back to loopback (proxy UNREACHABLE from the guest)", listenAddr, err)
			fmt.Printf("Warning: %s\n", warn)
			if aerr := appendDegradedWarning(ledger, s.Caller, warn); aerr != nil {
				cleanupVolumes()
				_ = st.Transition(state.StatusFailed, state.ActorController, "audit egress-bind degraded-warning append failed: "+aerr.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: audit egress-bind degraded warning for %s: %w", taskID, aerr)
			}
			lp, err = m.Egress.ListenForTaskOn(ctx, taskID, "")
		}
		if err != nil {
			cleanupVolumes()
			// Without a per-task listener we cannot safely attribute traffic,
			// so fail closed rather than falling back to the forgeable header.
			_ = st.Transition(state.StatusFailed, state.ActorController, "egress listener failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: egress listener for %s: %w", taskID, err)
		}
		defer lp.Close()
		egressAddr = lp.Addr()
		rawEgressAddr = egressAddr
		if tcDataplane {
			// The tc contract injects egress_proxy=169.254.68.5:<port>
			// regardless of where the listener actually landed (see above).
			if _, port, perr := net.SplitHostPort(egressAddr); perr == nil {
				egressAddr = net.JoinHostPort(network.TapDataplaneGatewayIP, port)
			}
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

	// Host-side tap attach for the rootless jail: when the monitor will run
	// under NEWUSER+NEWPID, TUNSETIFF is impossible from inside (no
	// CAP_NET_ADMIN in the host netns), so the tap is opened and programmed
	// here and inherited as an fd (vec0:transport=fd). The manager's copy of
	// the fd closes when StartTask returns; the workload holds its own.
	tapName := ""
	if s.Network.Enabled {
		tapName = s.Network.TAP
	}
	tapFile, tapFD, err := prepareTapFD(tapName, rootlessJailActive(uidRange))
	if err != nil {
		cleanupVolumes()
		_ = st.Transition(state.StatusFailed, state.ActorController, "tap fd setup failed: "+err.Error())
		state.SaveState(taskID, st)
		return err
	}
	if tapFile != nil {
		defer tapFile.Close()
	}

	// Per-task network data plane (P1-A): when a tap is in use, allocate the
	// guest IP from the bridge subnet (in-memory IPAM; the guest self-assigns
	// the address handed down as pvm_ip= on the kernel command line) and
	// attach the per-task TC egress filter whose whitelist map is pinned at
	// /sys/fs/bpf/pvm/<taskID>/. The BPF program's SSRF floor exempts the
	// gateway and the guest's own IP (RewriteConstants at load), so the
	// default route stays usable while other RFC1918 destinations drop.
	//
	// Degraded semantics: the BPF floor is defense in depth BELOW the L7
	// egress proxy, which remains the enforcement point. An attach failure
	// (no root/CAP_BPF, unmounted bpffs, no clsact) therefore degrades with
	// an audit security:degraded_warning instead of failing the task — the
	// same contract the jail's degraded mode follows. An IPAM failure is
	// different: it is a config/exhaustion error, not an environment gap, so
	// it fails closed.
	guestIP := ""
	detachNet := func() {}
	// dnsTeardown stops the P1-B DNS-learn proxy/sweeper and unregisters the
	// learner; a no-op when dns_learn_enabled is off.
	dnsTeardown := func() {}
	if s.Network.Enabled && tapName != "" {
		var ipam *network.IPAM
		filterAttached := false
		dpAttached := false
		// dnsGateway is where the guest's default resolver points (the
		// bridge gateway in bridge mode, the fixed tc gateway otherwise);
		// the DNS-learn proxy prefer-binds there.
		var dnsGateway net.IP

		// bridgePlane selects the classic P1-A data plane (per-bridge IPAM +
		// TAP-egress whitelist filter). It is the default; in tc mode it only
		// runs as the FALLBACK when the tc attach failed and the spec still
		// names a bridge (documented degraded composition).
		bridgePlane := !tcDataplane
		if tcDataplane {
			// P2 bridgeless tc data plane: the guest gets the FIXED
			// link-local 169.254.68.6 (same inside every sandbox), no IPAM,
			// no bridge. tap_ingress subsumes the egress filter's floor
			// (policy + SNAT on guest-originated traffic) and owns the
			// whitelist pin at the same standard path, so the whitelist CLI
			// and dnslearn work unchanged; the classic TAP-egress filter is
			// NOT attached (its host->guest direction is exempted by the
			// fixed addresses anyway). Attach failure degrades with an audit
			// warning; with a bridge configured we fall back to the classic
			// plane below, otherwise the task continues degraded (the L7
			// proxy via pvm-gw remains the enforcement point when it exists).
			guestIP = network.TapDataplaneGuestIP
			dnsGateway = net.ParseIP(network.TapDataplaneGatewayIP)
			if _, derr := network.AttachTapDataplane(taskID, tapName, ""); derr != nil {
				warn := fmt.Sprintf("tc dataplane attach failed for tap %s: %v; "+
					"running WITHOUT the bridgeless TC NAT/policy plane", tapName, derr)
				fmt.Printf("Warning: %s\n", warn)
				if aerr := appendDegradedWarning(ledger, s.Caller, warn); aerr != nil {
					cleanupVolumes()
					_ = st.Transition(state.StatusFailed, state.ActorController, "audit tc-dataplane degraded-warning append failed: "+aerr.Error())
					state.SaveState(taskID, st)
					return fmt.Errorf("container: audit tc-dataplane degraded warning for %s: %w", taskID, aerr)
				}
				if s.Network.Bridge != "" {
					bridgePlane = true
					egressAddr = rawEgressAddr // undo the fixed-gateway injection
				}
			} else {
				dpAttached = true
			}
		}
		var ierr error
		if bridgePlane {
			ipam, ierr = network.SharedIPAM(s.Network.GatewayIP)
			if ierr != nil {
				cleanupVolumes()
				_ = st.Transition(state.StatusFailed, state.ActorController, "guest IPAM init failed: "+ierr.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: guest IPAM for %s: %w", taskID, ierr)
			}
			var gip net.IP
			if s.Network.GuestIP != "" {
				gip, ierr = ipam.AllocateGuest(taskID, s.Network.GuestIP)
			} else {
				gip, ierr = ipam.Allocate(taskID)
			}
			if ierr != nil {
				cleanupVolumes()
				_ = st.Transition(state.StatusFailed, state.ActorController, "guest IP allocation failed: "+ierr.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: guest IP for %s: %w", taskID, ierr)
			}
			guestIP = gip.String()
			dnsGateway = ipam.GatewayIP()
			// Transparent L7 REDIRECT rules (bridge plane): now that the guest
			// IP exists, steer its :80/:443 into the wildcard listener started
			// earlier. Failure degrades with evidence — the explicit proxy
			// path keeps enforcing.
			if transparentPort != 0 {
				if terr := network.EnableTransparentL7(taskID, guestIP, transparentPort); terr != nil {
					warn := fmt.Sprintf("transparent L7 redirect install failed: %v; egress enforcement stays explicit-proxy", terr)
					fmt.Printf("Warning: %s\n", warn)
					if aerr := appendDegradedWarning(ledger, s.Caller, warn); aerr != nil {
						cleanupVolumes()
						_ = st.Transition(state.StatusFailed, state.ActorController, "audit transparent-l7-rule degraded-warning append failed: "+aerr.Error())
						state.SaveState(taskID, st)
						return fmt.Errorf("container: audit transparent-l7-rule degraded warning for %s: %w", taskID, aerr)
					}
				} else {
					transparentGuestIP = guestIP
				}
			}
			if _, ferr := network.AttachEgressFilter(tapName, taskID, ipam.GatewayIP(), gip); ferr != nil {
				warn := fmt.Sprintf("tc egress filter attach failed for tap %s: %v; "+
					"running WITHOUT the BPF IP-floor (L7 egress proxy remains the enforcement point)", tapName, ferr)
				fmt.Printf("Warning: %s\n", warn)
				if aerr := appendDegradedWarning(ledger, s.Caller, warn); aerr != nil {
					// The degraded warning is the ONLY auditable trace that this
					// task runs without the BPF floor; fail closed rather than boot
					// a downgraded sandbox with no evidence (mirrors the jail
					// degraded-warning contract above).
					if ipam != nil { // nil in tc mode (no IPAM there)
						ipam.Release(taskID)
					}
					cleanupVolumes()
					_ = st.Transition(state.StatusFailed, state.ActorController, "audit tc-filter degraded-warning append failed: "+aerr.Error())
					state.SaveState(taskID, st)
					return fmt.Errorf("container: audit tc-filter degraded warning for %s: %w", taskID, aerr)
				}
			} else {
				filterAttached = true
			}
		}
		// Symmetric teardown (mirrors SetupBridge's rollback style): detach
		// the tc dataplane (filters + pins + sweeper) and/or the classic
		// filter, unpin maps, release the registry entry and free the guest
		// IP. Runs on every return path after this point, including the
		// normal task-exit path below.
		detachNet = func() {
			if dpAttached {
				if derr := network.DetachTapDataplane(taskID); derr != nil {
					fmt.Printf("Warning: tc dataplane detach for %s: %v\n", taskID, derr)
				}
			}
			if filterAttached {
				if derr := network.DetachTaskFilter(taskID, tapName); derr != nil {
					fmt.Printf("Warning: tc filter detach for %s: %v\n", taskID, derr)
				}
			}
			// Transparent L7 rules (bridge plane): remove before the rest of
			// the network goes away.
			if transparentPort != 0 && transparentGuestIP != "" {
				if err := network.DisableTransparentL7(taskID, transparentGuestIP, transparentPort); err != nil {
					fmt.Printf("Warning: transparent L7 removal for %s: %v\n", taskID, err)
				}
			}
			// Inbound port mappings (bridge plane): remove rules + records.
			if err := network.CleanupTaskPortMappings(taskID); err != nil {
				fmt.Printf("Warning: port mapping cleanup for %s: %v\n", taskID, err)
			}
			if ipam != nil {
				ipam.Release(taskID)
			}
		}

		// Record the resolved network posture on the state record so the
		// API (and operators) can map host ports without re-deriving it.
		if st.Metadata == nil {
			st.Metadata = map[string]string{}
		}
		st.Metadata["guest_ip"] = guestIP
		st.Metadata["tap"] = tapName
		if dpAttached {
			st.Metadata["dataplane"] = "tc"
		} else if bridgePlane {
			st.Metadata["dataplane"] = "bridge"
		}

		// Inbound port mappings ([[network.port_mappings]]): bridge plane
		// only — the bridgeless tc plane reverse-NATs established sessions
		// and has no static inbound NAT, so declared mappings degrade with
		// an audited warning instead of failing the launch.
		if len(s.Network.PortMappings) > 0 {
			if bridgePlane && !dpAttached {
				for _, pm := range s.Network.PortMappings {
					if err := network.AddPortMapping(network.PortMapping{
						TaskID:    taskID,
						HostPort:  pm.HostPort,
						GuestPort: pm.GuestPort,
						GuestIP:   guestIP,
						Protocol:  pm.Protocol,
					}); err != nil {
						cleanupVolumes()
						_ = st.Transition(state.StatusFailed, state.ActorController, "port mapping failed: "+err.Error())
						state.SaveState(taskID, st)
						return fmt.Errorf("container: port mapping for %s: %w", taskID, err)
					}
				}
			} else {
				warn := fmt.Sprintf("port mappings require the bridge dataplane; %d mapping(s) skipped (tc plane active)", len(s.Network.PortMappings))
				fmt.Printf("Warning: %s\n", warn)
				if aerr := appendDegradedWarning(ledger, s.Caller, warn); aerr != nil {
					cleanupVolumes()
					_ = st.Transition(state.StatusFailed, state.ActorController, "audit portmap degraded-warning append failed: "+aerr.Error())
					state.SaveState(taskID, st)
					return fmt.Errorf("container: audit portmap degraded warning for %s: %w", taskID, aerr)
				}
			}
		}

		// DNS-learned domain egress (P1-B): snoop the guest's resolver
		// traffic with a per-task UDP proxy and insert the resolved public
		// IPs of ALLOWLISTED domains into the whitelist map attached above,
		// TTL-bounded. The learner shares the filter's fate: when the TC
		// attach degraded, map writes fail tolerated and the learned table
		// only feeds the L7 gateway's rebinding guard — audited below. The
		// guest is not told about the proxy (no kernel-cmdline knob): a guest
		// using the gateway as its resolver (the default) is snooped
		// automatically; anything else just misses learning while the L7
		// proxy still enforces.
		if s.Network.DNSLearnEnabled {
			allow := append([]string(nil), s.Network.EgressAllowDomains...)
			for _, r := range s.Network.EgressRules {
				host := r.Host
				if host == "" {
					host = r.SNI
				}
				if host == "" || (r.Allow != nil && !*r.Allow) {
					continue // deny rules never learn
				}
				allow = append(allow, host)
			}
			learnTTL, _ := time.ParseDuration(s.Network.LearnTTL) // spec-validated
			learner, lerr := dnslearn.New(dnslearn.Config{
				TaskID:       taskID,
				TapName:      tapName,
				AllowDomains: allow,
				LearnTTL:     learnTTL,
				Upstream:     s.Network.DNSUpstream,
				MaxEntries:   s.Network.MaxLearnedEntries,
				Ledger:       ledger,
			})
			if lerr != nil {
				cleanupVolumes()
				_ = st.Transition(state.StatusFailed, state.ActorController, "dns learner config failed: "+lerr.Error())
				state.SaveState(taskID, st)
				return fmt.Errorf("container: dns learner for %s: %w", taskID, lerr)
			}
			if !filterAttached {
				warn := "dns_learn_enabled but the tc egress filter is degraded: " +
					"learned entries are tracked in-memory only (L7 rebinding guard active, " +
					"no eBPF whitelist-map updates)"
				fmt.Printf("Warning: %s\n", warn)
				if aerr := ledger.Append(audit.Record{
					Phase:    audit.PhaseExec,
					Subject:  s.Caller,
					Action:   "security:degraded_warning",
					Decision: audit.DecisionAllow,
					Reason:   warn,
				}); aerr != nil {
					// Same fail-closed contract as the tc-filter degraded warning
					// above: this row is the only evidence of table-only learning.
					if ipam != nil { // nil in tc mode (no IPAM there)
						ipam.Release(taskID)
					}
					cleanupVolumes()
					_ = st.Transition(state.StatusFailed, state.ActorController, "audit dns-learn degraded-warning append failed: "+aerr.Error())
					state.SaveState(taskID, st)
					return fmt.Errorf("container: audit dns-learn degraded warning for %s: %w", taskID, aerr)
				}
			}
			dnsCtx, dnsCancel := context.WithCancel(context.Background())
			learner.Run(dnsCtx)
			// dnsGateway is the bridge gateway in bridge mode and the fixed
			// 169.254.68.5 (pvm-gw) in tc mode; binding it may fail without
			// root — StartProxy then falls back to loopback (audited there).
			preferBind := net.JoinHostPort(dnsGateway.String(), "53")
			if addr, perr := learner.StartProxy(dnsCtx, preferBind); perr != nil {
				// Even the loopback fallback failed: continue WITHOUT DNS
				// learning (L7 proxy still enforces), with evidence.
				learner.AuditDegraded(fmt.Sprintf("dns proxy bind failed: %v; task runs without DNS learning", perr))
			} else {
				fmt.Printf("DNS-learn proxy for %s on %s (upstream %s)\n", taskID, addr, learner.Upstream())
			}
			dnslearn.Register(learner)
			dnsTeardown = func() {
				dnslearn.Unregister(taskID, learner)
				dnsCancel()
				learner.Close()
			}
		}
	}
	defer detachNet()
	// Runs before detachNet (LIFO): stop snooping before the map goes away.
	defer dnsTeardown()

	// UML seccomp userspace mode is an opt-in guest-integrity trade-off
	// (see SecuritySpec.UMLSeccomp): every on/auto launch MUST leave an
	// auditable trace naming the configured mode and arch. mode=auto can
	// silently fall back to ptrace inside the guest (undetectable from the
	// host), so the record notes that fallback is possible. Fail closed on
	// append failure, matching the spec-evidence/degraded-warning contract.
	if s.Security.UMLSeccomp == "on" || s.Security.UMLSeccomp == "auto" {
		params := map[string]interface{}{
			"mode": s.Security.UMLSeccomp,
			"arch": runtime.GOARCH,
		}
		reason := "UML seccomp userspace mode enabled: guest kernel integrity no longer guaranteed (in-guest cgroup enforcement advisory); host jail boundary unaffected"
		if s.Security.UMLSeccomp == "auto" {
			params["note"] = "fallback possible: kernel may silently use ptrace mode"
		}
		if err := ledger.Append(audit.Record{
			Phase:    audit.PhaseExec,
			Subject:  s.Caller,
			Action:   "security:uml_seccomp",
			Params:   params,
			Decision: audit.DecisionAllow,
			Reason:   reason,
		}); err != nil {
			cleanupVolumes()
			_ = st.Transition(state.StatusFailed, state.ActorController, "audit uml_seccomp append failed: "+err.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf("container: audit uml_seccomp for %s: %w", taskID, err)
		}
	}

	// Build kernel args from the TaskSpec. Pass the resolved rootfs so the
	// kernel command line matches what we actually provisioned. egressAddr is
	// the host:port of this task's dedicated egress listener (authoritative
	// attribution source); the task id is NOT exposed to the guest.
	args, err := buildTaskArgs(s, sockPath, resolvedRootfs, egressAddr, volumeArgs, tapFD)
	if err != nil {
		cleanupVolumes()
		_ = st.Transition(state.StatusFailed, state.ActorController, "kernel args rejected: "+err.Error())
		state.SaveState(taskID, st)
		return err
	}
	// Hand the allocated guest IP to the guest (it self-assigns this address
	// on vec0). Injected here rather than inside buildTaskArgs because the
	// IP only exists after the IPAM step above; same injection pattern as
	// egress_proxy= (validate-then-append).
	if guestIP != "" {
		if err := validateKernelField("guest ip", guestIP); err != nil {
			cleanupVolumes()
			_ = st.Transition(state.StatusFailed, state.ActorController, "kernel args rejected: "+err.Error())
			state.SaveState(taskID, st)
			return err
		}
		args = append(args, fmt.Sprintf("pvm_ip=%s", guestIP))
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
	var logFile io.WriteCloser
	if interactive, _ := ctx.Value(KeyInteractive).(bool); !interactive {
		lf, outW, errW, e := setupConsoleWriters(taskID)
		if e != nil {
			cleanupVolumes()
			_ = st.Transition(state.StatusFailed, state.ActorController, "console log setup failed: "+e.Error())
			state.SaveState(taskID, st)
			return e
		}
		logFile = lf
		ctx = context.WithValue(ctx, uml.KeyStdoutWriter, outW)
		ctx = context.WithValue(ctx, uml.KeyStderrWriter, errW)
		defer func() {
			_ = lf.Close()
			_ = outW.Close()
			_ = errW.Close()
		}()
	} else {
		defer func() {
			if logFile != nil {
				_ = logFile.Close()
			}
		}()
	}

	// Ready: sandbox process about to start.
	_ = st.Transition(state.StatusReady, state.ActorController, "provisioned")
	state.SaveState(taskID, st)

	jailEnv, err := jail.SetupJail(jail.Config{
		TaskID:                taskID,
		AllowInsecureDegraded: s.Security.AllowInsecureDegraded,
		EnforceHostSeccomp:    s.Security.EnforceHostSeccomp,
		EnforceLandlock:       s.Security.EnforceLandlock,
		UIDBase:               uidBase,
		UIDRangeSize:          uidRange,
	})
	if err != nil {
		cleanupVolumes()
		_ = st.Transition(state.StatusFailed, state.ActorController, "jail setup failed: "+err.Error())
		state.SaveState(taskID, st)
		return err
	}
	if jailEnv != nil {
		defer jailEnv.Cleanup()
		if jailEnv.IsolationActive() {
			// Same jail path-rewrite as the legacy Boot path: the kernel
			// must open the overlay/vhost socket/tun through in-jail binds.
			// With the fd transport the tap is inherited instead, so
			// /dev/net/tun is NOT bound into the jail.
			tap := tapName
			if tapFD >= 0 {
				tap = ""
			}
			var vols []jail.VolumeMapping
			args, vols = routeLaunchThroughJail(args, tap)
			jailEnv.Config.Volumes = vols
			grantMonitorImageAccess(jailEnv, vols, uidBase)
		}
		if tapFile != nil {
			ctx = context.WithValue(ctx, uml.KeyExtraFiles, []*os.File{tapFile})
		}
		ctx = context.WithValue(ctx, uml.KeyJailEnv, jailEnv)
	}

	// Console session (non-interactive agent tasks): same binding as the
	// Boot path. The launcher creates a stdin pipe because logFile != nil,
	// but without an attached session nothing bridges it — envd SendStdin
	// finds no session (404) and any guest workload waiting on stdin/EOF
	// blocks forever. Attach + tee BEFORE Start; SetStdin right after.
	var consoleSession *console.Session
	if logFile != nil {
		consoleSession = console.Default().Attach(taskID)
		ctx = context.WithValue(ctx, uml.KeyConsoleTee, consoleSession)
	}
	pid, p, err := m.Launcher.Start(ctx, s.Kernel.Path, args, logFile)
	state.StampPID(st, pid) // pid + starttime stamp (recycled-pid guard)
	if err != nil {
		if consoleSession != nil {
			console.Default().Detach(taskID)
		}
		cleanupVolumes()
		_ = st.Transition(state.StatusFailed, state.ActorController, "launch failed: "+err.Error())
		state.SaveState(taskID, st)
		return err
	}
	if consoleSession != nil {
		consoleSession.SetStdin(p.Stdin)
		// StartTask blocks until the kernel exits; release the session when
		// the task is done (mirrors the Boot path's deferred Detach).
		defer console.Default().Detach(taskID)
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
		// Fail closed when limits were REQUESTED, same contract as the
		// Boot path: do NOT SignalReady — a workload must never run
		// outside its confirmed cgroup limits. Kill the barrier-blocked
		// stage-1 child and reap it (the deferred jailEnv.Cleanup closes
		// the sync pipe as a second fail-closed net). Without requested
		// limits the failure stays a warning (cgroup-less test/CI hosts).
		if memBytes > 0 || s.Runtime.CPU > 0 {
			if p != nil && p.Cmd != nil && p.Cmd.Process != nil {
				_ = p.Cmd.Process.Kill()
				_ = m.Launcher.Wait(p)
			}
			cleanupVolumes()
			_ = st.Transition(state.StatusFailed, state.ActorController, "cgroup setup failed with requested limits: "+setupErr.Error())
			state.SaveState(taskID, st)
			return fmt.Errorf(
				"container: cgroup setup for %s with requested limits: %w",
				taskID, setupErr,
			)
		}
		fmt.Printf("Warning: failed to setup cgroup limits for %s: %v\n", taskID, setupErr)
	}
	// Unblock stage 1 only AFTER the cgroup write: stage 2 is forked past
	// this barrier and inherits the stage-1 cgroup (see jail.SignalReady).
	jailEnv.SignalReady()

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
			m.Autopause.SetDeepPause(taskID, s.Lifecycle.DeepPause)
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

// logMaxBytesFromEnv / logKeepFromEnv read the rotation policy. Defaults in
// internal/logx (8 MiB × 3).
func logMaxBytesFromEnv() int64 {
	if v := os.Getenv("PVM_LOG_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func logKeepFromEnv() int {
	if v := os.Getenv("PVM_LOG_KEEP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// setupConsoleWriters opens the rotating console log set for containerID:
// the combined console.log (rotated; replaces the unbounded plain file) plus
// per-stream console.out.log / console.err.log. On failure it degrades to
// DevNull for the affected writers — the boot must survive a read-only log
// dir, mirroring setupConsoleFile's fallback contract.
func setupConsoleWriters(containerID string) (combined, stdoutW, stderrW io.WriteCloser, err error) {
	dir, derr := state.ContainerDir(containerID)
	if derr != nil {
		return nil, nil, nil, derr
	}
	logDir := filepath.Join(dir, "logs")
	max, keep := logMaxBytesFromEnv(), logKeepFromEnv()

	open := func(name string) io.WriteCloser {
		r, rerr := logx.NewRotator(filepath.Join(logDir, name), max, keep)
		if rerr != nil {
			log.Default().Warnf("console log %s unavailable for %s (%v); routing that stream to %s", name, containerID, rerr, os.DevNull)
			null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			return null
		}
		return r
	}

	// Honor the hardened log dir contract from log.SetupConsoleLog.
	if mkErr := os.MkdirAll(logDir, 0o700); mkErr == nil {
		_ = os.Chmod(logDir, 0o700)
	}
	combined = open("console.log")
	stdoutW = open("console.out.log")
	stderrW = open("console.err.log")
	return combined, stdoutW, stderrW, nil
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
// tapFD >= 0 replaces the vec0 tap transport with the fd transport: the tap
// was attached host-side and is inherited by the workload as that fd.
func buildLegacyArgs(ctx context.Context, cfg *config.ContainerConfig, tapFD int) ([]string, error) {
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
		// Ephemeral appends the ubd 'r' flag (ubd0r=): the host opens the
		// backing file O_RDONLY and marks the disk read-only, so a guest
		// that remounts the root rw — or writes the raw /dev/ubda — still
		// cannot reach the file. The separate "ro" token below keeps the
		// ROOT MOUNT read-only as well (belt-and-suspenders, mirroring the
		// vhost path's read-only backend + cmdline ro pairing).
		if cfg.Ephemeral {
			args = append(args, fmt.Sprintf("ubd0r=%s", resolved))
		} else {
			args = append(args, fmt.Sprintf("ubd0=%s", resolved))
		}
		args = append(args, "root=/dev/ubda")
	}
	// Root mount mode: ephemeral sandboxes mount the rootfs read-only so
	// nothing the guest writes persists (same contract as buildTaskArgs).
	if cfg.Ephemeral {
		args = append(args, "ro")
	} else {
		args = append(args, "rw")
	}
	// Network device: vec0 (see buildTaskArgs — legacy eth0=tuntap is gone in
	// Linux >= 6.16, only the vector transport remains). tapFD >= 0 selects
	// the rootless fd transport: the tap was attached host-side by
	// prepareTapFD and is inherited as that fd (UML vector
	// 'transport=fd,fd=N'), so the monitor never touches /dev/net/tun.
	if cfg.NetworkTap != "" {
		if err := validateKernelField("tap device", cfg.NetworkTap); err != nil {
			return nil, err
		}
		if tapFD >= 0 {
			args = append(args, fmt.Sprintf("vec0:transport=fd,fd=%d,vec=0", tapFD))
		} else {
			args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,depth=128,gro=1", cfg.NetworkTap))
		}
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

// appendDegradedWarning records a security:degraded_warning audit row — the
// ONLY auditable trace that a task runs with a downgraded enforcement layer.
// Callers fail closed when the append itself fails (a downgraded sandbox must
// never boot without evidence); mirrors the jail degraded-warning contract.
func appendDegradedWarning(ledger *audit.Ledger, caller, reason string) error {
	return ledger.Append(audit.Record{
		Phase:    audit.PhaseExec,
		Subject:  caller,
		Action:   "security:degraded_warning",
		Decision: audit.DecisionAllow,
		Reason:   reason,
	})
}

// buildTaskArgs builds the UML command-line from a TaskSpec. Mirrors the legacy
// path but reads everything from the validated spec. resolvedRootfs is the
// block path the kernel must mount (the overlay) and is the single source of
// truth — the caller already created it. egressAddr, when non-empty, is the
// host:port of this task's dedicated egress listener; it is forwarded to the
// guest so the guest dials it as its HTTP proxy. The task id is deliberately
// NOT passed: the guest cannot be trusted with its own attribution id, and
// the per-task listener binds the id by closure on the host side instead.
// tapFD >= 0 replaces the vec0 tap transport with the fd transport (see
// buildLegacyArgs).
func buildTaskArgs(s *spec.TaskSpec, vhostSock, resolvedRootfs, egressAddr string, volumeArgs []string, tapFD int) ([]string, error) {
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
		// Boot exactly the validated (resolved, contained) path. Ephemeral
		// uses the ubd 'r' flag (ubd0r=) for device-level read-only — the
		// same guarantee as the legacy path: the host opens the backing
		// file O_RDONLY, so guest writes cannot reach it even if the root
		// is remounted rw.
		if s.Workspace.Ephemeral {
			args = append(args, fmt.Sprintf("ubd0r=%s", resolved))
		} else {
			args = append(args, fmt.Sprintf("ubd0=%s", resolved))
		}
		args = append(args, "root=/dev/ubda")
	}
	// resolvedRootfs empty: no block device was provisioned (BaseImage
	// unset), so the kernel boots init-only with no ubd0=/root= args.
	// Root mount mode: ephemeral sandboxes boot read-only — no guest write
	// can reach the host disk. Writable scratch space is the guest init's
	// tmpfs (see uml/init-ephemeral.sh); persistent volumes (hostfs mounts)
	// are unaffected by the root's mount mode.
	if s.Workspace.Ephemeral {
		args = append(args, "ro")
	} else {
		args = append(args, "rw")
	}
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
		if tapFD >= 0 {
			// Rootless fd transport (prepareTapFD): the tap fd is inherited,
			// no /dev/net/tun or CAP_NET_ADMIN needed inside the jail.
			args = append(args, fmt.Sprintf("vec0:transport=fd,fd=%d,vec=0", tapFD))
		} else {
			args = append(args, fmt.Sprintf("vec0:transport=tap,ifname=%s,depth=128,gro=1", s.Network.TAP))
		}
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
	// UML fast seccomp userspace mode (runtime kernel param since mainline
	// 6.16 on x86_64; zalexdev aarch64 port): `seccomp=on|auto`. "off" (the
	// spec default) passes nothing, keeping the kernel default. Arch-neutral:
	// the same cmdline parameter is parsed on both architectures.
	if s.Security.UMLSeccomp != "" && s.Security.UMLSeccomp != "off" {
		args = append(args, fmt.Sprintf("seccomp=%s", s.Security.UMLSeccomp))
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

// resolveAutoDataplane picks the data plane for specs that say
// network.dataplane = "auto". Policy (in priority order):
//
//  1. port mappings pin bridge — the bridgeless tc plane has no static
//     inbound NAT;
//  2. L7 egress rules or a flat allow/block domain list pin bridge —
//     transparent HTTP(S) interception (iptables REDIRECT into the L7
//     gateway) is wired on the bridge path;
//  3. an unprivileged process cannot load TC eBPF at all — bridge;
//  4. otherwise prefer tc (no iptables footprint); its attach path
//     degrades back to the classic plane when a bridge/gateway exists.
//
// Pure function of the spec + the process euid: deterministic and
// unit-testable.
func resolveAutoDataplane(s *spec.TaskSpec) string {
	if len(s.Network.PortMappings) > 0 {
		return spec.DataplaneBridge
	}
	if len(s.Network.EgressRules) > 0 ||
		len(s.Network.EgressAllowDomains) > 0 ||
		len(s.Network.EgressBlockDomains) > 0 {
		return spec.DataplaneBridge
	}
	if os.Geteuid() != 0 {
		return spec.DataplaneBridge
	}
	return spec.DataplaneTC
}
