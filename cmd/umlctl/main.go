package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"uml-container/internal/config"
	"uml-container/internal/container"
	"uml-container/internal/uml"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: umlctl [start|stop|create]")
		os.Exit(1)
	}
	cmd := os.Args[1]

	startCmd := flag.NewFlagSet("start", flag.ExitOnError)
	name := startCmd.String("name", "default", "Container name")
	virtio := startCmd.Bool("virtio", false, "Use virtio-uml")
	rootfs := startCmd.String("rootfs", "rootfs.img", "Path to rootfs")
	mem := startCmd.String("mem", "512M", "Memory size")
	kernel := startCmd.String("kernel", "linux", "UML Kernel binary")
	netTap := startCmd.String("tap", "", "Network tap device (optional)")
	initCmd := startCmd.String("init", "/sbin/init", "Init command inside container")

	if cmd == "start" {
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

		manager := container.NewManager(&uml.DefaultLauncher{})
		fmt.Printf("Starting container %s with virtio=%v\n", *name, *virtio)
		err := manager.Start(context.Background(), cfg)
		if err != nil {
			fmt.Printf("Error starting: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Command %s not fully implemented yet\n", cmd)
	}
}
