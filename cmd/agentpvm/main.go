package main

import (
	"flag"
	"fmt"
	"os"
	"uml-container/internal/api"
	"uml-container/internal/ebpf"
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
		
		runCmd.Parse(os.Args[2:])
		
		fmt.Printf("Starting sandbox %s...\n", *name)
		if *useVhost {
			fmt.Println("Starting qemu-storage-daemon for vhost-user block device...")
			sock, daemonCmd, err := vhost.StartStorageDaemon(*name, *rootfs)
			if err != nil {
				fmt.Printf("Error starting vhost: %v\n", err)
			} else {
				defer daemonCmd.Process.Kill()
				fmt.Printf("Vhost socket ready at %s\n", sock)
			}
		}
		// Assuming we call container.Manager.Start here ...
		fmt.Println("Sandbox running. (Mocked for CLI architecture demo)")

	case "api":
		apiCmd := flag.NewFlagSet("api", flag.ExitOnError)
		port := apiCmd.Int("port", 8080, "API Server Port")
		apiCmd.Parse(os.Args[2:])
		
		if err := api.StartE2BServer(*port); err != nil {
			fmt.Printf("API Server Error: %v\n", err)
		}

	case "snapshot":
		if len(os.Args) < 4 {
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
		if len(os.Args) < 5 {
			fmt.Println("Usage: agentpvm network whitelist add <domain> <ip>")
			return
		}
		domain := os.Args[3]
		ip := os.Args[4]
		ebpf.UpdateWhitelist(domain, ip)

	default:
		fmt.Println("Unknown command:", cmd)
	}
}
