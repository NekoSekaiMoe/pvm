package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"uml-container/internal/api"
	"uml-container/internal/cgroup"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/ebpf"
	"uml-container/internal/network"
	"uml-container/internal/snapshot"
	"uml-container/internal/vhost"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: agentpvm [run|api|snapshot|network]")
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
		kernel := runCmd.String("kernel", "./bin/linux", "Kernel path")
		initPath := runCmd.String("init", "/init.sh", "Init script path")
		memory := runCmd.String("memory", "512M", "Container memory")

		runCmd.Parse(os.Args[2:])

		fmt.Printf("Starting sandbox %s...\n", *name)
		var sockPath string
		if *useVhost {
			fmt.Println("Starting qemu-storage-daemon for vhost-user block device...")
			sock, daemonCmd, err := vhost.StartStorageDaemon(*name, *rootfs)
			if err != nil {
				fmt.Printf("Error starting vhost: %v\n", err)
			} else {
				defer daemonCmd.Process.Kill()
				sockPath = sock
				fmt.Printf("Vhost socket ready at %s\n", sock)
			}
		}

		mgr := container.NewManager(nil)
		cfg := &config.ContainerConfig{
			ID:              *name,
			Name:            *name,
			Rootfs:          *rootfs,
			Kernel:          *kernel,
			Init:            *initPath,
			Memory:          *memory,
			UseVirtio:       *useVhost,
			VhostUserSocket: sockPath,
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
