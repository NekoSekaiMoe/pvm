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
	"uml-container/internal/state"
	"uml-container/internal/uml"
)

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
		kernel := startCmd.String("kernel", "linux", "UML Kernel binary")
		netTap := startCmd.String("tap", "", "Network tap device (optional)")
		initCmd := startCmd.String("init", "/sbin/init", "Init command inside container")
		overlay := startCmd.Bool("overlay", false, "Use overlayfs (rootfs is base image)")
		rm := startCmd.Bool("rm", false, "Remove container and state after exit")
		it := startCmd.Bool("it", false, "Interactive mode (direct shell login, bypass logs)")
		volume := startCmd.String("volume", "", "Host directory to mount via hostfs (e.g. /host:/container)")

		startCmd.Parse(os.Args[2:])

		cfg := &config.ContainerConfig{
			ID:         *name,
			Name:       *name,
			Kernel:     *kernel,
			Rootfs:     *rootfs,
			Memory:     *mem,
			UseVirtio:  *virtio,
			Init:       *initCmd,
			NetworkTap: *netTap,
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
		err := manager.Start(ctx, cfg)
		
		if *rm {
			fmt.Println("Cleaning up container state and files (--rm)...")
			dir, err := state.ContainerDir(*name)
			if err == nil {
				os.RemoveAll(dir)
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
			} else {
				fmt.Printf("Image %s pulled successfully.\n", baseName)
			}
		} else {
			fmt.Println("Usage: umlctl image pull <docker-image-name>")
		}

	case "network":
		netCmd := flag.NewFlagSet("network", flag.ExitOnError)
		netCmd.Parse(os.Args[2:])
		args := netCmd.Args()
		if len(args) >= 2 {
			subcmd := args[0]
			name := args[1]
			if subcmd == "create" {
				err := network.SetupBridge(name, "", "10.0.0.1/24")
				if err != nil {
					fmt.Printf("Error creating network: %v\n", err)
				} else {
					fmt.Printf("Network %s created.\n", name)
				}
			} else if subcmd == "rm" {
				err := network.DeleteBridge(name, "")
				if err != nil {
					fmt.Printf("Error deleting network: %v\n", err)
				} else {
					fmt.Printf("Network %s deleted.\n", name)
				}
			} else {
				fmt.Printf("Unknown network subcommand: %s\n", subcmd)
				fmt.Println("Usage: umlctl network [create|rm] <name>")
			}
		} else {
			fmt.Println("Usage: umlctl network [create|rm] <name>")
		}

	case "logs":
		if len(os.Args) < 3 {
			fmt.Println("Usage: umlctl logs <container-id>")
			return
		}
		id := os.Args[2]
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(id) {
			fmt.Printf("Invalid container ID: %s\n", id)
			return
		}
		dir, err := state.ContainerDir(id)
		if err != nil {
			fmt.Printf("Failed to get container dir: %v\n", err)
			return
		}
		logPath := filepath.Join(dir, "logs", "console.log")
		file, err := os.Open(logPath)
		if err != nil {
			fmt.Printf("Failed to open logs for %s: %v\n", id, err)
			return
		}
		defer file.Close()
		io.Copy(os.Stdout, file)

	case "ps":
		dirs, err := os.ReadDir(state.RootDir)
		if err != nil {
			fmt.Printf("Failed to read containers directory: %v\n", err)
			return
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
	}
}
