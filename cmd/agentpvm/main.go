package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"uml-container/internal/api"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/cow"
	"uml-container/internal/ebpf"
	"uml-container/internal/network"
	"uml-container/internal/snapshot"
	"uml-container/internal/vhost"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: agentpvm [run|api|webui|snapshot|network|cgroup|cow]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "run":
		// Similar to umlctl start but explicitly prepares vhost-user
		runCmd := flag.NewFlagSet("run", flag.ExitOnError)
		name := runCmd.String("name", "agent1", "Sandbox name")
		rootfs := runCmd.String("rootfs", "rootfs.img", "Root filesystem")
		useVhost := runCmd.Bool("vhost", true, "Use vhost-user-blk for storage")
		nativeVhost := runCmd.Bool("native-vhost", false, "Use experimental native Go vhost-user backend")
		kernel := runCmd.String("kernel", "./bin/linux", "Kernel path")
		initPath := runCmd.String("init", "/init.sh", "Init script path")
		memory := runCmd.String("memory", "512M", "Container memory")
		cpu := runCmd.Int("cpu", 0, "CPU limit (0 means no limit)")
		netTap := runCmd.String("net-tap", "", "Network tap device to use")
		nativeVhostNet := runCmd.Bool("native-vhost-net", false, "Use native Go vhost-user-net backend for networking")

		runCmd.Parse(os.Args[2:])

		if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(*name) {
			fmt.Println("Error: Invalid container name format")
			os.Exit(1)
		}

		fmt.Printf("Starting sandbox %s...\n", *name)
		var sockPath string
		var vhostProcess *exec.Cmd
		if *useVhost {
			if *nativeVhost {
				fmt.Println("Starting native vhost-user backend...")
				sock, _, err := vhost.StartNativeDaemon(*name, *rootfs)
				if err != nil {
					fmt.Printf("Error starting native vhost: %v\n", err)
					os.Exit(1)
				}
				sockPath = sock
			} else {
				fmt.Println("Starting qemu-storage-daemon for vhost-user block device...")
				sock, daemonCmd, err := vhost.StartStorageDaemon(*name, *rootfs)
				if err != nil {
					fmt.Printf("Error starting vhost: %v\n", err)
					os.Exit(1)
				}
				vhostProcess = daemonCmd
				defer vhostProcess.Process.Kill()
				sockPath = sock
				fmt.Printf("Vhost socket ready at %s\n", sock)
			}
		}

		mgr := container.NewManager(nil)
		if *cpu < 0 {
			fmt.Printf("Error: CPU limit cannot be negative\n")
			os.Exit(1)
		}
		memBytes, err := config.ParseMemory(*memory)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		cfg := &config.ContainerConfig{
			ID:              *name,
			Name:            *name,
			Rootfs:          *rootfs,
			Kernel:          *kernel,
			Init:            *initPath,
			Memory:          *memory,
			MemoryBytes:     memBytes,
			CPU:             *cpu,
			UseVirtio:       *useVhost,
			VhostUserSocket: sockPath,
			NetworkTap:      *netTap,
		}

		if *netTap != "" && *nativeVhostNet {
			fmt.Println("Starting native vhost-user-net backend...")
			// Create a default bridge name or assume it's set up
			netSock, _, err := vhost.StartNativeNetDaemon(*name, *netTap, "")
			if err != nil {
				fmt.Printf("Error starting native vhost net: %v\n", err)
			} else {
				cfg.VhostNetSocket = netSock
			}
		}

		if err := mgr.Start(context.Background(), cfg); err != nil {
			fmt.Printf("Container start failed: %v\n", err)
		} else {
			fmt.Println("Sandbox exited.")
		}

	case "api":
		apiCmd := flag.NewFlagSet("api", flag.ExitOnError)
		port := apiCmd.Int("port", 8080, "API Server Port")
		apiCmd.Parse(os.Args[2:])

		if err := api.StartE2BServer(*port); err != nil {
			fmt.Printf("API Server Error: %v\n", err)
		}

	case "webui":
		// WebUI / management API. Equivalent to `api` but defaults to the
		// dashboard port and is the intended entry point for the glassmorphism
		// WebUI embedded in the binary (see webui/embed.go).
		webuiCmd := flag.NewFlagSet("webui", flag.ExitOnError)
		port := webuiCmd.Int("port", 3000, "Port to run WebUI on")
		webuiCmd.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage of webui:\n")
			fmt.Fprintf(os.Stderr, "  Starts the WebUI + E2B-compatible management API.\n")
			webuiCmd.PrintDefaults()
		}
		webuiCmd.Parse(os.Args[2:])
		if err := api.StartE2BServer(*port); err != nil {
			fmt.Printf("WebUI server failed: %v\n", err)
			os.Exit(1)
		}

	case "cow":
		// Create a qcow2 Copy-on-Write overlay over a base image. Keeps the
		// base image read-only and writes diverge into the overlay.
		cowCmd := flag.NewFlagSet("cow", flag.ExitOnError)
		backing := cowCmd.String("backing", "", "Backing (base) image path")
		overlay := cowCmd.String("overlay", "", "Output qcow2 overlay path")
		backingFormat := cowCmd.String("backing-format", "raw", "Backing file format (raw/qcow2)")
		cowCmd.Parse(os.Args[2:])
		if *backing == "" || *overlay == "" {
			fmt.Println("Usage: agentpvm cow -backing <base.img> -overlay <overlay.qcow2> [-backing-format raw]")
			os.Exit(1)
		}
		if err := cow.CreateOverlay(*backing, *overlay, *backingFormat); err != nil {
			fmt.Printf("CoW overlay creation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CoW overlay created: %s -> %s\n", *backing, *overlay)

	case "snapshot":
		if len(os.Args) < 5 {
			fmt.Println("Usage: agentpvm snapshot [export|import] <id> <file.tgz>")
			return
		}
		sub := os.Args[2]
		id := os.Args[3]
		file := os.Args[4]

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

	case "network":
		if len(os.Args) < 4 {
			fmt.Println("Usage: agentpvm network [whitelist|qos]")
			return
		}
		sub := os.Args[2]
		if sub == "whitelist" && len(os.Args) >= 6 && os.Args[3] == "add" {
			domain := os.Args[4]
			ip := os.Args[5]
			ebpf.UpdateWhitelist(domain, ip)
		} else if sub == "qos" && len(os.Args) >= 5 {
			tap := os.Args[3]
			rate := os.Args[4]
			if err := network.SetupQoS(tap, rate); err != nil {
				fmt.Printf("QoS Error: %v\n", err)
			} else {
				fmt.Printf("QoS limit set to %s on %s\n", rate, tap)
			}
		}

	case "cgroup":
		if len(os.Args) < 4 {
			fmt.Println("Usage: agentpvm cgroup [freeze|thaw] <id>")
			return
		}
		sub := os.Args[2]
		id := os.Args[3]
		cg := cgroup.NewManager()
		if sub == "freeze" {
			if err := cg.Freeze(id); err != nil {
				fmt.Printf("Freeze failed: %v\n", err)
			} else {
				fmt.Println("Container frozen successfully (0 CPU usage)")
			}
		} else if sub == "thaw" {
			if err := cg.Thaw(id); err != nil {
				fmt.Printf("Thaw failed: %v\n", err)
			} else {
				fmt.Println("Container thawed successfully (CPU restored)")
			}
		}

	default:
		fmt.Println("Unknown command:", cmd)
	}
}
