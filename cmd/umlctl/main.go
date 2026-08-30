package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/image"
	"uml-container/internal/network"
	"uml-container/internal/snapshot"
	"uml-container/internal/spec"
	"uml-container/internal/state"
	"uml-container/internal/uml"
)

// idRegex validates task/container ids: ^[-_A-Za-z0-9]+$. Precompiled once
// at package load and shared by every subcommand. Same shape as the id
// validators in internal/{api,state,cgroup,snapshot,container}; each package
// keeps its own precompiled symbol to avoid an import cycle via a shared helper.
var idRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// netNameRegex validates bridge names for `umlctl network create/rm`:
// letters/digits/dot/underscore/dash, 1..15 chars (the kernel's IFNAMSIZ
// limit minus the NUL). Anything else would either fail deep inside
// iproute2 or smuggle extra arguments into the invoked commands.
var netNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

// validNetName applies netNameRegex plus the names the charset alone
// accepts but must never reach iproute2 or state-path derivation: "." and
// ".." (they resolve to the current/parent directory in derived paths) and
// leading "-" (iproute2 would parse it as a flag value).
func validNetName(name string) bool {
	return name != "." && name != ".." &&
		!strings.HasPrefix(name, "-") && netNameRegex.MatchString(name)
}

// loadLaunchConfig loads a TaskSpec TOML but returns only the launch-relevant
// subset. umlctl is a thin UML launcher: it deliberately ignores the control
// planes (identity/egress/tools/approval/artifacts/lifecycle) which belong to
// agentpvm. Reading the same TOML format keeps the two binaries interoperable.
func loadLaunchConfig(path string) (*spec.TaskSpec, error) {
	return spec.LoadFile(path)
}

// boolFalseExplicit reports whether the caller explicitly passed -name=false
// on this FlagSet. flag.Visit only reports flags that were SET on the command
// line, so an explicit "false" is distinguishable from the untouched default
// only by inspecting the visited flag values. The -config merge below only
// flips booleans ON from the spec, so an explicit CLI opt-out must win over
// the file (same flag-beats-file rule as every other boolean override).
func boolFalseExplicit(fs *flag.FlagSet, name string) bool {
	explicitFalse := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name && f.Value.String() == "false" {
			explicitFalse = true
		}
	})
	return explicitFalse
}

// ephemeralFalseExplicit reports whether the caller explicitly passed
// -ephemeral=false on this FlagSet (see boolFalseExplicit).
func ephemeralFalseExplicit(fs *flag.FlagSet) bool {
	return boolFalseExplicit(fs, "ephemeral")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: umlctl [start|image|logs|ps|network]")
		os.Exit(1)
	}
	cmd := os.Args[1]

	switch cmd {
	case "start":
		startCmd := flag.NewFlagSet("start", flag.ExitOnError)
		name := startCmd.String("name", "default", "Container name")
		virtio := startCmd.Bool("virtio", false, "Use virtio-uml")
		rootfs := startCmd.String("rootfs", "rootfs.img", "Path to rootfs (or base image)")
		mem := startCmd.String("mem", "512M", "Memory size")
		cpu := startCmd.Int("cpu", 0, "CPU limit (0 means no limit)")
		kernel := startCmd.String("kernel", "linux", "UML Kernel binary")
		netTap := startCmd.String("tap", "", "Network tap device (optional)")
		initCmd := startCmd.String("init", "/sbin/init", "Init command inside container")
		overlay := startCmd.Bool("overlay", false, "Use overlayfs (rootfs is base image)")
		ephemeral := startCmd.Bool("ephemeral", false, "Non-persistent container: read-only rootfs, discard container state after exit")
		rm := startCmd.Bool("rm", false, "Remove container and state after exit")
		it := startCmd.Bool("it", false, "Interactive mode (direct shell login, bypass logs)")
		volume := startCmd.String("volume", "", "Host directory to mount via hostfs (e.g. /host:/container)")
		configPath := startCmd.String("config", "", "Load container settings from TOML (overrides the flags below; default: none)")
		insecureDegraded := startCmd.Bool("insecure-allow-degraded", false, "Allow running in degraded security mode")

		startCmd.Parse(os.Args[2:])

		// -config optionally overrides the launch-related flags. umlctl is a
		// THIN launcher: it only consumes the launch fields (kernel/rootfs/
		// mem/cpu/init/net), never the full TaskSpec control planes — those
		// are agentpvm's job.
		if *configPath != "" {
			if s, err := loadLaunchConfig(*configPath); err == nil {
				if *name == "default" && s.Runtime.Name != "" {
					*name = s.Runtime.Name
				}
				if s.Kernel.Path != "" {
					*kernel = s.Kernel.Path
				}
				if s.Workspace.BaseImage != "" {
					*rootfs = s.Workspace.BaseImage
				}
				if s.Workspace.Init != "" {
					*initCmd = s.Workspace.Init
				}
				if s.Runtime.Memory != "" {
					*mem = s.Runtime.Memory
				}
				if s.Runtime.CPU > 0 {
					*cpu = s.Runtime.CPU
				}
				if s.Network.TAP != "" {
					*netTap = s.Network.TAP
				}
				// Only FLIP virtio ON from the spec, never off: a zero-value
				// s.Kernel.Virtio must not silently disable a -virtio the caller
				// explicitly passed on the command line (consistent with the
				// "config augments flags" rule used by every other field above).
				if s.Kernel.Virtio {
					*virtio = true
				}
				// Same flip-on rule for ephemeral: workspace.ephemeral=true in the
				// config enables non-persistent mode unless the caller explicitly
				// passed -ephemeral=false (flag.Visit detects explicit setting,
				// mirroring agentpvm run's boolean override handling).
				if s.Workspace.Ephemeral && !ephemeralFalseExplicit(startCmd) {
					*ephemeral = true
				}
				// Same flip-on rule for insecure-allow-degraded: the config's
				// true must not override an explicit -insecure-allow-degraded=false
				// on the command line. Allowing the file to silently re-enable
				// degraded mode after the caller opted out would weaken the
				// security posture the user explicitly requested.
				if s.Security.AllowInsecureDegraded && !boolFalseExplicit(startCmd, "insecure-allow-degraded") {
					*insecureDegraded = true
				}
			} else {
				// A bad -config must not silently fall back to flag defaults:
				// the caller asked for a specific launch shape and booting a
				// different one (e.g. without the config's ephemeral setting)
				// would be surprising. Fail fast with a non-zero exit.
				fmt.Fprintf(os.Stderr, "Error: -config %s load failed: %v\n", *configPath, err)
				os.Exit(1)
			}
		}

		if !idRegex.MatchString(*name) {
			fmt.Println("Error: Invalid container name format")
			os.Exit(1)
		}

		if *cpu < 0 {
			fmt.Printf("Error: CPU limit cannot be negative\n")
			os.Exit(1)
		}
		memBytes, err := config.ParseMemory(*mem)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		cfg := &config.ContainerConfig{
			ID:                    *name,
			Name:                  *name,
			Kernel:                *kernel,
			Rootfs:                *rootfs,
			Memory:                *mem,
			MemoryBytes:           memBytes,
			CPU:                   *cpu,
			UseVirtio:             *virtio,
			Init:                  *initCmd,
			NetworkTap:            *netTap,
			Ephemeral:             *ephemeral,
			AllowInsecureDegraded: *insecureDegraded,
		}

		// Ephemeral and overlay clone are mutually exclusive: an ephemeral
		// container boots its rootfs read-only, so copying the base into a
		// private layer would be pure waste.
		if *ephemeral && *overlay {
			fmt.Println("Error: -ephemeral and -overlay are mutually exclusive " +
				"(ephemeral boots the rootfs read-only, no layer is cloned)")
			os.Exit(1)
		}

		if *overlay {
			if err := image.CreateLayer(*name); err != nil {
				fmt.Printf("Failed to create overlay layer: %v\n", err)
				os.Exit(1)
			}
			mergedImg, err := image.MountLayer(*name, *rootfs)
			if err != nil {
				fmt.Printf("Failed to prepare overlay image: %v\n", err)
				os.Exit(1)
			}
			// mergedImg is a real ext4 image file; ubd0=<file> + root=/dev/ubda works.
			cfg.Rootfs = mergedImg
		}

		manager := container.NewManager(&uml.DefaultLauncher{})

		// If interactive mode, we instruct the manager to not intercept logs
		// We'll pass it in context or adjust manager interface for MVP
		ctx := context.Background()
		if *it {
			ctx = context.WithValue(ctx, container.KeyInteractive, true)
			if *initCmd == "/sbin/init" {
				cfg.Init = "/bin/sh" // Force shell if interactive and default init
			}
		}

		// Support volume via simple hostfs string parsing (Host:Container)
		if *volume != "" {
			parts := strings.SplitN(*volume, ":", 2)
			if len(parts) == 2 {
				ctx = context.WithValue(ctx, container.KeyVolumeHost, parts[0])
				ctx = context.WithValue(ctx, container.KeyVolumeGuest, parts[1])
			} else {
				fmt.Println("Invalid volume format. Expected host:guest")
				os.Exit(1)
			}
		}

		fmt.Printf("Starting container %s...\n", *name)
		err = manager.Start(ctx, cfg)

		// Ephemeral implies -rm: discard the container dir (state, logs) after
		// exit so nothing of the run persists. The clone guard is the same as
		// -rm: while clones still branch from this container, keep the files.
		if *rm || *ephemeral {
			fmt.Println("Cleaning up container state and files...")
			// A clone's overlay backing reaches into this container's dir;
			// keep the files while clones still branch from it.
			if perr := snapshot.PrepareDelete(*name); perr != nil {
				fmt.Printf("Warning: keeping container %s files: %v\n", *name, perr)
			} else {
				dir, err := state.ContainerDir(*name)
				if err == nil {
					os.RemoveAll(dir)
				}
			}
		}

		if err != nil {
			fmt.Printf("Container exited with error: %v\n", err)
			os.Exit(1)
		}

	case "image":
		imageCmd := flag.NewFlagSet("image", flag.ExitOnError)
		imageCmd.Parse(os.Args[2:])
		args := imageCmd.Args()
		if len(args) > 0 && args[0] == "pull" {
			baseName := "alpine"
			if len(args) > 1 {
				baseName = args[1]
			}
			fmt.Printf("Pulling docker image %s...\n", baseName)
			if err := image.Pull(baseName); err != nil {
				fmt.Printf("Failed to pull image: %v\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Image %s pulled successfully.\n", baseName)
			}
		} else {
			fmt.Println("Usage: umlctl image pull <docker-image-name>")
			os.Exit(1)
		}

	case "network":
		netCmd := flag.NewFlagSet("network", flag.ExitOnError)
		netCmd.Parse(os.Args[2:])
		args := netCmd.Args()
		if len(args) >= 2 {
			subcmd := args[0]
			name := args[1]
			if !validNetName(name) {
				fmt.Printf("Invalid network name %q (want ^[a-zA-Z0-9._-]{1,15}$, not . or ..)\n", name)
				os.Exit(1)
			}
			if subcmd == "create" {
				// Subnet allocation: the persistent registry picks the next free
				// /24 from the pool (default 10.64.0.0/12), skipping host nets.
				// When the registry is unavailable (read-only state root) fall
				// back to the historical default so create keeps working.
				gwCIDR := "10.0.0.1/24"
				if reg, rerr := network.LoadNetworkRegistry(os.Getenv("PVM_STATE_ROOT")); rerr == nil {
					if allocated, aerr := reg.Allocate(name); aerr == nil {
						gwCIDR = allocated
					} else {
						fmt.Printf("Warning: subnet allocation failed (%v); using %s\n", aerr, gwCIDR)
					}
				}
				err := network.SetupBridge(name, "", gwCIDR)
				if err != nil {
					fmt.Printf("Error creating network: %v\n", err)
					os.Exit(1)
				} else {
					fmt.Printf("Network %s created on %s.\n", name, gwCIDR)
				}
			} else if subcmd == "rm" {
				if reg, rerr := network.LoadNetworkRegistry(os.Getenv("PVM_STATE_ROOT")); rerr == nil {
					reg.Release(name)
				}
				err := network.DeleteBridge(name, "")
				if err != nil {
					fmt.Printf("Error deleting network: %v\n", err)
					os.Exit(1)
				} else {
					fmt.Printf("Network %s deleted.\n", name)
				}
			} else {
				fmt.Printf("Unknown network subcommand: %s\n", subcmd)
				fmt.Println("Usage: umlctl network [create|rm] <name>")
				os.Exit(1)
			}
		} else {
			fmt.Println("Usage: umlctl network [create|rm] <name>")
			os.Exit(1)
		}

	case "logs":
		if len(os.Args) < 3 {
			fmt.Println("Usage: umlctl logs <container-id>")
			os.Exit(1)
		}
		id := os.Args[2]
		if !idRegex.MatchString(id) {
			fmt.Printf("Invalid container ID: %s\n", id)
			os.Exit(1)
		}
		dir, err := state.ContainerDir(id)
		if err != nil {
			fmt.Printf("Failed to get container dir: %v\n", err)
			os.Exit(1)
		}
		logPath := filepath.Join(dir, "logs", "console.log")
		file, err := os.Open(logPath)
		if err != nil {
			fmt.Printf("Failed to open logs for %s: %v\n", id, err)
			os.Exit(1)
		}
		defer file.Close()
		io.Copy(os.Stdout, file)

	case "ps":
		dirs, err := os.ReadDir(state.RootDir)
		if err != nil {
			fmt.Printf("Failed to read containers directory: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%-15s %-15s %-10s\n", "CONTAINER ID", "STATUS", "PID")
		for _, d := range dirs {
			if d.IsDir() {
				st, err := state.LoadState(d.Name())
				if err == nil {
					fmt.Printf("%-15s %-15s %-10d\n", st.ID, st.Status, st.PID)
				}
			}
		}

	default:
		fmt.Printf("Command %s not recognized\n", cmd)
		os.Exit(1)
	}
}
