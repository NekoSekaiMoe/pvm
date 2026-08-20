// Command agentpvm is the real "agent sandbox" entry point.
//
// Unlike umlctl (a thin UML container launcher), agentpvm consumes a full
// TaskSpec (plan.md §9 control contract) and wires every control plane:
// identity broker, L7 egress gateway, tool/policy gateway, artifact gate,
// approval tickets, incident controller, warm pool + quota.
//
// Config sources, in priority order:
//  1. -config <file.toml>           explicit
//  2. ./uml/agentpvm.toml           default location
//  3. built-in safe defaults        if neither exists (with a warning)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"uml-container/internal/api"
	"uml-container/internal/approval"
	"uml-container/internal/artifact"
	"uml-container/internal/audit"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/cow"
	"uml-container/internal/ebpf"
	"uml-container/internal/identity"
	"uml-container/internal/incident"
	"uml-container/internal/log"
	"uml-container/internal/network"
	"uml-container/internal/network/egress"
	"uml-container/internal/policy"
	"uml-container/internal/snapshot"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/vhost"
)

// defaultConfigPath is consulted when -config is not given.
const defaultConfigPath = "uml/agentpvm.toml"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: agentpvm [run|api|webui|snapshot|network|cgroup|cow|gate|approval|pool]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "run":
		runCmd(os.Args[2:])
	case "api":
		apiCmd(os.Args[2:])
	case "webui":
		webuiCmd(os.Args[2:])
	case "cow":
		cowCmd(os.Args[2:])
	case "snapshot":
		snapshotCmd(os.Args[2:])
	case "network":
		networkCmd(os.Args[2:])
	case "cgroup":
		cgroupCmd(os.Args[2:])
	// --- new sandbox-control subcommands ---
	case "gate":
		gateCmd(os.Args[2:])
	case "approval":
		approvalCmd(os.Args[2:])
	case "pool":
		poolCmd(os.Args[2:])
	default:
		fmt.Println("Unknown command:", cmd)
	}
}

// resolveConfigPath implements the -config / ./uml/agentpvm.toml / defaults rule.
func resolveConfigPath(explicit string) (string, bool) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			fmt.Fprintf(os.Stderr, "config: %s not found: %v\n", explicit, err)
			return "", false
		}
		return explicit, true
	}
	if _, err := os.Stat(defaultConfigPath); err == nil {
		return defaultConfigPath, true
	}
	fmt.Fprintf(os.Stderr, "config: no -config given and %s missing; using safe defaults\n", defaultConfigPath)
	return "", false
}

// runCmd boots a sandbox from a TaskSpec.
//
// In addition to -config (the full TaskSpec TOML), the launch-relevant
// fields can be overridden on the command line. These mirror umlctl's thin
// launcher flags so the same kernel/rootfs/init/net knobs work on both
// binaries; CLI flags take precedence over the config file.
//
// There is deliberately no -vhost flag: the agent path MUST use the
// vhost-user-blk backend with a per-task qcow2 CoW overlay (spec contract),
// so UseVhostBlk comes from the config file only. For the raw ubd direct
// mount, use the umlctl thin launcher instead.
func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to TaskSpec TOML (default: ./uml/agentpvm.toml)")
	name := fs.String("name", "", "Override task id (default: spec.runtime.name)")
	debug := fs.Bool("debug", false, "Enable debug logging")
	// Launch overrides (applied after loading the spec). Empty/zero means
	// "keep whatever the config file provided".
	rootfs := fs.String("rootfs", "", "Override workspace.base_image (rootfs / backing image path)")
	kernel := fs.String("kernel", "", "Override kernel.path (UML kernel binary)")
	initCmd := fs.String("init", "", "Override workspace.init (in-guest init command)")
	netEnabled := fs.Bool("net", false, "Enable guest networking (overrides network.enabled)")
	netTap := fs.String("net-tap", "", "Host TAP device name (overrides network.tap)")
	fs.Parse(args)

	if *debug {
		log.Default().SetLevel(log.LevelDebug)
	}

	path, ok := resolveConfigPath(*configPath)
	var s *spec.TaskSpec
	if ok {
		loaded, err := spec.LoadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config: load %s: %v\n", path, err)
			os.Exit(1)
		}
		s = loaded
		fmt.Printf("Loaded TaskSpec from %s (fingerprint %s)\n", path, s.Fingerprint()[:12])
	} else {
		s = safeDefaultSpec()
		fmt.Printf("Using built-in safe defaults (caller=%s)\n", s.Caller)
	}

	// Apply CLI launch overrides (flag > config > default).
	// Boolean flags need explicit-set detection (e.g. -net=false must be
	// able to turn OFF a config-provided network.enabled=true), so only
	// apply the override when the flag was actually given on the command line.
	netGiven := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "net" {
			netGiven = true
		}
	})
	if *rootfs != "" {
		s.Workspace.BaseImage = *rootfs
	}
	if *kernel != "" {
		s.Kernel.Path = *kernel
	}
	if *initCmd != "" {
		s.Workspace.Init = *initCmd
	}
	if netGiven {
		s.Network.Enabled = *netEnabled
	}
	if *netTap != "" {
		s.Network.Enabled = true // a TAP name implies the caller wants networking
		s.Network.TAP = *netTap
	}

	taskID := *name
	if taskID == "" {
		taskID = s.Runtime.Name
	}
	if taskID == "" {
		taskID = "agent-task"
	}
	if !idRegex.MatchString(taskID) {
		fmt.Fprintln(os.Stderr, "Error: Invalid task id format")
		os.Exit(1)
	}

	// --- assemble control planes ---
	ledger, err := audit.Open(taskID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		os.Exit(1)
	}
	broker, err := identity.NewBroker(nil, identity.StaticStore{}, ledger, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identity: %v\n", err)
		os.Exit(1)
	}
	eg := egress.NewGateway()
	eg.AttachLedger(ledger)
	// NOTE: we intentionally do NOT open a shared eg.Listen() listener here.
	// Manager.StartTask opens a per-task listener via ListenForTask, whose
	// handler binds the task id by closure (unforgeable attribution) and
	// injects its host:port into the guest as egress_proxy=. The old shared
	// listener used the forgeable X-Task-Id header; keeping it around would
	// both leak a useless port and print a misleading "Egress gateway
	// listening on" line that no traffic actually flows through.

	incidentCtl := incident.NewController(ledger, broker, incident.Hooks{
		FreezeRuntime: func(id string) error {
			return cgroup.NewManager().Freeze(id)
		},
		Terminate: func(id string) error {
			st, err := state.LoadState(id)
			if err == nil && st.PID > 0 {
				if p, err := os.FindProcess(st.PID); err == nil {
					return p.Kill()
				}
			}
			return nil
		},
	})

	// Attach the task-specific ledger so this task's egress audit rows are
	// attributed to it, not to the controller's default ledger task.
	eg.AttachTaskLedger(taskID, ledger)

	mgr := container.NewManager(nil)
	mgr.Broker = broker
	mgr.Egress = eg
	mgr.IncidentHandler = &incidentAdapter{ctl: incidentCtl}
	// Register the task's policy gateway with the API's /exec dispatcher.
	// Without this, /api/exec always returns 403 even though /api/policy/:task
	// shows the rules (the two used to read from different registries).
	api.RegisterPolicyGateway(taskID, policy.NewGateway(policy.CompileRules(
		rulesFromSpec(s.Tools),
	), ledger))

	fmt.Printf("Starting sandbox %s...\n", taskID)
	if err := mgr.StartTask(context.Background(), taskID, s); err != nil {
		fmt.Fprintf(os.Stderr, "Container start failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Sandbox exited.")
}

// safeDefaultSpec is the failsafe TaskSpec used when no config file exists.
// Everything is default-deny: no network, no tools, minimal scope. The point
// is that even a misconfigured launch is SAFE, not useful.
func safeDefaultSpec() *spec.TaskSpec {
	s := &spec.TaskSpec{
		Version: spec.SpecVersion,
		Caller:  os.Getenv("USER"),
		Tenant:  "default",
		Runtime: spec.RuntimeSpec{Name: "agent-task", CPU: 1, Memory: "512M"},
		Workspace: spec.WorkspaceSpec{
			BaseImage: "rootfs.img",
			Init:      "/sbin/init",
		},
		// UseVhostBlk=true: the agent path contract — per-task qcow2 CoW
		// overlay served over vhost-user-blk (raw bases work too; the overlay
		// is always qcow2). The ubd direct-mount path is umlctl's job.
		Kernel:    spec.KernelSpec{Path: "./bin/linux", UseVhostBlk: true},
		Network:   spec.NetworkSpec{Enabled: false}, // default deny
		Lifecycle: spec.LifecycleSpec{OnAnomaly: "pause", TTL: "1h"},
	}
	_ = s.Validate()
	return s
}

// incidentAdapter bridges Manager.IncidentHandler -> incident.Controller.
type incidentAdapter struct{ ctl *incident.Controller }

func (a *incidentAdapter) OnBudgetExceeded(taskID string) {
	_, _ = a.ctl.Handle(context.Background(), incident.Anomaly{
		TaskID: taskID, Severity: incident.SeverityMedium,
		Signal: "budget:wall_time_exceeded", Detail: "max_wall_time reached",
	})
}

// rulesFromSpec converts the TaskSpec's tool rules into the {Name,Action,
// Effect,Reason} shape policy.CompileRules expects. Kept here so agentpvm
// owns the spec->policy translation and cmd/agentpvm does not reach into
// policy internals for every launch.
func rulesFromSpec(in []spec.ToolRule) []struct{ Name, Action, Effect, Reason string } {
	out := make([]struct{ Name, Action, Effect, Reason string }, 0, len(in))
	for _, r := range in {
		out = append(out, struct{ Name, Action, Effect, Reason string }{
			Name: r.Name, Action: r.Action, Effect: r.Effect, Reason: r.Reason,
		})
	}
	return out
}

// apiCmd / webuiCmd start the management API.
func apiCmd(args []string) {
	fs := flag.NewFlagSet("api", flag.ExitOnError)
	port := fs.Int("port", 8080, "API Server Port")
	fs.Parse(args)
	if err := api.StartE2BServer(*port); err != nil {
		fmt.Fprintf(os.Stderr, "API Server Error: %v\n", err)
	}
}

func webuiCmd(args []string) {
	fs := flag.NewFlagSet("webui", flag.ExitOnError)
	port := fs.Int("port", 3000, "Port to run WebUI on")
	fs.Parse(args)
	if err := api.StartE2BServer(*port); err != nil {
		fmt.Fprintf(os.Stderr, "WebUI server failed: %v\n", err)
		os.Exit(1)
	}
}

func cowCmd(args []string) {
	fs := flag.NewFlagSet("cow", flag.ExitOnError)
	backing := fs.String("backing", "", "Backing (base) qcow2 image path")
	overlay := fs.String("overlay", "", "Output qcow2 overlay path")
	compact := fs.String("compact", "", "Compact an existing qcow2 overlay in place (rebuild, drop zero clusters, no qemu-img)")
	toRaw := fs.String("to-raw", "", "Convert any image (raw/qcow2, +backing chain) to a standalone raw image: -to-raw <src> [-overlay <dst>]")
	toQcow2 := fs.String("to-qcow2", "", "Convert any image to a standalone qcow2: -to-qcow2 <src> [-overlay <dst>]")
	fs.Parse(args)
	if *compact != "" {
		stats, err := cow.Compact(context.Background(), *compact)
		if err != nil {
			fmt.Printf("Compact failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Compacted %s: %d -> %d bytes (%d clusters copied, %d zeroed, %d dropped)\n",
			*compact, stats.BeforeBytes, stats.AfterBytes, stats.ClustersCopied, stats.ClustersZeroed, stats.ClustersDropped)
		return
	}
	if *toRaw != "" {
		dst := *overlay
		if dst == "" {
			dst = trimExt(*toRaw) + ".img"
		}
		if err := cow.ConvertToRaw(context.Background(), *toRaw, dst); err != nil {
			fmt.Printf("Convert to raw failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Converted %s (%s) -> %s (raw)\n", *toRaw, cow.SniffFormat(*toRaw), dst)
		return
	}
	if *toQcow2 != "" {
		dst := *overlay
		if dst == "" {
			dst = trimExt(*toQcow2) + ".qcow2"
		}
		if err := cow.ConvertToQcow2(context.Background(), *toQcow2, dst, cow.ConvertDefaultOpt); err != nil {
			fmt.Printf("Convert to qcow2 failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Converted %s (%s) -> %s (qcow2)\n", *toQcow2, cow.SniffFormat(*toQcow2), dst)
		return
	}
	if *backing == "" || *overlay == "" {
		fmt.Println("Usage: agentpvm cow -backing <base.qcow2> -overlay <overlay.qcow2>")
		fmt.Println("       agentpvm cow -compact <overlay.qcow2>")
		fmt.Println("       agentpvm cow -to-raw <src> [-overlay <dst.img>]")
		fmt.Println("       agentpvm cow -to-qcow2 <src> [-overlay <dst.qcow2>]")
		os.Exit(1)
	}
	if err := cow.CreateOverlay(context.Background(), *backing, *overlay); err != nil {
		fmt.Printf("CoW overlay creation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("CoW overlay created: %s -> %s\n", *backing, *overlay)
}

// trimExt strips the final path extension (used to derive a default dest name
// for convert operations).
func trimExt(p string) string {
	d := p
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '.' {
			d = p[:i]
			break
		}
		if p[i] == '/' {
			break
		}
	}
	return d
}

func snapshotCmd(args []string) {
	if len(args) < 3 {
		fmt.Println("Usage: agentpvm snapshot [export|import] <id> <file.tgz>")
		return
	}
	sub, id, file := args[0], args[1], args[2]
	if sub == "export" {
		if err := snapshot.Export(id, file); err != nil {
			fmt.Printf("Export failed: %v\n", err)
		} else {
			fmt.Println("Snapshot exported successfully to", file)
		}
	} else if sub == "import" {
		if err := snapshot.Import(file, id); err != nil {
			fmt.Printf("Import failed: %v\n", err)
		} else {
			fmt.Println("Snapshot imported successfully as", id)
		}
	}
}

func networkCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: agentpvm network [whitelist|qos]")
		return
	}
	sub := args[0]
	if sub == "whitelist" && len(args) >= 4 && args[1] == "add" {
		ebpf.UpdateWhitelist(args[2], args[3])
	} else if sub == "qos" && len(args) >= 3 {
		if err := network.SetupQoS(args[1], args[2]); err != nil {
			fmt.Printf("QoS Error: %v\n", err)
		} else {
			fmt.Printf("QoS limit set to %s on %s\n", args[2], args[1])
		}
	}
}

func cgroupCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: agentpvm cgroup [freeze|thaw] <id>")
		return
	}
	sub, id := args[0], args[1]
	cg := cgroup.NewManager()
	switch sub {
	case "freeze":
		if err := cg.Freeze(id); err != nil {
			fmt.Printf("Freeze failed: %v\n", err)
		} else {
			fmt.Println("Container frozen successfully (0 CPU usage)")
		}
	case "thaw":
		if err := cg.Thaw(id); err != nil {
			fmt.Printf("Thaw failed: %v\n", err)
		} else {
			fmt.Println("Container thawed successfully (CPU restored)")
		}
	}
}

// gateCmd runs the Artifact Gate standalone on a bundle and reports the
// verdict. The bundle is read from the file pointed to by -bundle and verified
// against the default verifiers; the per-step result and overall pass/fail are
// printed. The ledger root is scoped to the bundle's directory so the audit
// row lands next to the bundle.
func gateCmd(args []string) {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "Artifact bundle JSON file")
	fs.Parse(args)
	if *bundlePath == "" {
		fmt.Println("Usage: agentpvm gate -bundle <bundle.json>")
		os.Exit(1)
	}
	data, err := os.ReadFile(*bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate: read bundle %s: %v\n", *bundlePath, err)
		os.Exit(1)
	}
	var b artifact.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		fmt.Fprintf(os.Stderr, "gate: parse bundle: %v\n", err)
		os.Exit(1)
	}
	// Scope the audit ledger to the bundle's task id; fall back to no-ledger
	// if the bundle doesn't carry one or the path is not writable.
	var ledger *audit.Ledger
	if b.TaskID != "" {
		l, lerr := audit.Open(b.TaskID)
		if lerr == nil {
			ledger = l
		}
	}
	g := artifact.NewGate(ledger)
	v := g.Verify(&b)
	if v.Passed {
		fmt.Printf("PASS (hash=%s)\n", v.Hash)
		return
	}
	fmt.Printf("FAIL (hash=%s):\n", v.Hash)
	for step, status := range v.Step {
		fmt.Printf("  %s: %s\n", step, status)
	}
	os.Exit(1)
}

// approvalCmd lists/decides approval tickets by talking to the running API.
// It reads API_SECRET from the environment and hits /api/approvals so the
// state it shows is the live state of the controller, not an ephemeral store.
//
// API_SECRET is REQUIRED: there is no hardcoded fallback. A missing secret is
// a configuration error (we never want to silently authenticate as "secret").
// All HTTP calls go through a client with a finite timeout so a wedged API
// cannot hang the CLI indefinitely.
var cliHTTPClient = &http.Client{Timeout: 10 * time.Second}

func resolveAPISecret() (string, error) {
	secret := os.Getenv("API_SECRET")
	if secret == "" {
		return "", errors.New("API_SECRET environment variable is required (set it to the controller's PVM_API_SECRET)")
	}
	return secret, nil
}

func approvalCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: agentpvm approval [list]   (operates against $PVM_API / $API_SECRET)")
		return
	}
	base := os.Getenv("PVM_API")
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	secret, err := resolveAPISecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "approval: %v\n", err)
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		req, _ := http.NewRequest("GET", base+"/api/approvals", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := cliHTTPClient.Do(req)
		if err != nil {
			fmt.Printf("approval list: %v (is the API running at %s?)\n", err, base)
			return
		}
		defer resp.Body.Close()
		var tickets []approval.Ticket
		_ = json.NewDecoder(resp.Body).Decode(&tickets)
		if len(tickets) == 0 {
			fmt.Println("(no pending tickets)")
			return
		}
		for _, t := range tickets {
			fmt.Printf("%s\t%s\t%s\t%s\n", t.ID, t.Tool, t.Target, t.Why)
		}
	default:
		fmt.Println("unknown subcommand:", args[0])
	}
}

// poolCmd inspects or warms the sandbox pool by talking to the running API.
// As with approvalCmd, it operates against the live controller state.
func poolCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: agentpvm pool [stats|warm <template> <n>]   (operates against $PVM_API / $API_SECRET)")
		return
	}
	base := os.Getenv("PVM_API")
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	secret, err := resolveAPISecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pool: %v\n", err)
		os.Exit(1)
	}
	switch args[0] {
	case "stats":
		req, _ := http.NewRequest("GET", base+"/api/pool/stats", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := cliHTTPClient.Do(req)
		if err != nil {
			fmt.Printf("pool stats: %v (is the API running at %s?)\n", err, base)
			return
		}
		defer resp.Body.Close()
		var st struct {
			Ready   int `json:"ready"`
			Claimed int `json:"claimed"`
			Total   int `json:"total"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&st)
		fmt.Printf("ready=%d claimed=%d total=%d\n", st.Ready, st.Claimed, st.Total)
	default:
		fmt.Println("unknown subcommand:", args[0], "(warm is not yet implemented over HTTP)")
	}
}

// Compile-time guards that the unused-but-required imports are real (they are
// referenced via the type system even when a subcommand isn't exercised).
var (
	_ = config.ParseMemory
	_ = strings.TrimSpace
	_ = exec.Command
	_ = vhost.StartBlk
	_ = policy.NewGateway
	_ = spec.SpecVersion
)

// idRegex validates task/container ids: same shape as every other package
// (^[-_A-Za-z0-9]+$). Kept package-local rather than shared to avoid an extra
// import; the inline regexp.MustCompile that used to live in runCmd now
// reuses this single precompiled value.
var idRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
