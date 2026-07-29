package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/image"
	"uml-container/internal/state"
	"uml-container/internal/uml"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: umlctl [start|stop|create|image|logs|ps]")
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
			// Feature 1: OverlayFS Layer Creation
			if err := image.CreateLayer(*name); err != nil {
				fmt.Printf("Failed to create overlay layer: %v\n", err)
			} else {
				fmt.Printf("OverlayFS layers prepared in /var/lib/uml-container/containers/%s\n", *name)
			}
		}

		manager := container.NewManager(&uml.DefaultLauncher{})
		fmt.Printf("Starting container %s with virtio=%v\n", *name, *virtio)
		err := manager.Start(context.Background(), cfg)
		if err != nil {
			fmt.Printf("Error starting: %v\n", err)
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
			fmt.Printf("Pulling image %s...\n", baseName)
			if err := image.Pull(baseName); err != nil {
				fmt.Printf("Failed to pull image: %v\n", err)
			} else {
				fmt.Printf("Image %s pulled successfully.\n", baseName)
			}
		} else {
			fmt.Println("Usage: umlctl image pull [name]")
		}

	case "logs":
		if len(os.Args) < 3 {
			fmt.Println("Usage: umlctl logs <container-id>")
			return
		}
		id := os.Args[2]
		logPath := filepath.Join("/var/lib/uml-container/containers", id, "logs", "console.log")
		file, err := os.Open(logPath)
		if err != nil {
			fmt.Printf("Failed to open logs for %s: %v\n", id, err)
			return
		}
		defer file.Close()
		io.Copy(os.Stdout, file)

	case "ps":
		dirs, err := os.ReadDir("/var/lib/uml-container/containers")
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
		fmt.Printf("Command %s not fully implemented yet\n", cmd)
	}
}
