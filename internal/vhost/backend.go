package vhost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"uml-container/internal/state"
)

// StartNativeDaemon starts the experimental native Go vhost-user server
func StartNativeDaemon(containerID string, imagePath string) (string, *Server, error) {
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create dir: %v", err)
	}
	socketPath := filepath.Join(dir, "vhost-blk.sock")

	blk, err := NewBlockDevice(imagePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open block device %s: %v", imagePath, err)
	}

	server := NewServer(socketPath, blk, nil)
	if err := server.Start(); err != nil {
		return "", nil, fmt.Errorf("native vhost server failed to start: %v", err)
	}

	// For the native server, it runs in goroutines, so it's instantly ready
	return socketPath, server, nil
}

// StartStorageDaemon starts qemu-storage-daemon to provide a vhost-user-blk socket.
// Requires qemu-storage-daemon installed on the host.
func StartStorageDaemon(containerID string, imagePath string) (string, *exec.Cmd, error) {
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create dir: %v", err)
	}
	socketPath := filepath.Join(dir, "vhost-blk.sock")
	
	// If it already exists, remove it
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return "", nil, fmt.Errorf("failed to remove socket: %v", err)
	}

	formatDriver := "raw"
	if filepath.Ext(imagePath) == ".qcow2" {
		formatDriver = "qcow2"
	}

	if strings.Contains(imagePath, ",") {
		return "", nil, fmt.Errorf("invalid imagePath: cannot contain comma")
	}

	aioMode := "threads"
	if supportsIoUring() {
		aioMode = "io_uring"
	}

	cmd := exec.Command("qemu-storage-daemon",
		"--blockdev", fmt.Sprintf("driver=file,node-name=disk0,filename=%s,aio=%s", imagePath, aioMode),
		"--blockdev", fmt.Sprintf("driver=%s,node-name=format0,file=disk0", formatDriver),
		"--export", fmt.Sprintf("type=vhost-user-blk,id=export0,node-name=format0,addr.type=unix,addr.path=%s,writable=on", socketPath),
	)
	
	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("failed to start qemu-storage-daemon: %v", err)
	}
	
	// Wait for socket to be created
	found := false
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			found = true
			break
		}
		if cmd.Process != nil {
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				// Process dead
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	if !found {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		return "", nil, fmt.Errorf("timeout waiting for socket to be created: %s", socketPath)
	}
	
	return socketPath, cmd, nil
}

// StartNativeNetDaemon starts a native Go vhost-user server for virtio-net
func StartNativeNetDaemon(containerID string, tapName string, bridgeName string) (string, *Server, error) {
	dir := filepath.Join("/var/lib/uml-container/containers", containerID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", nil, err
	}
	socketPath := filepath.Join(dir, "vhost-net.sock")

	netDev, err := NewNetDevice(tapName, bridgeName)
	if err != nil {
		return "", nil, fmt.Errorf("failed to init net device: %v", err)
	}

	server := NewServer(socketPath, nil, netDev)
	if err := server.Start(); err != nil {
		return "", nil, fmt.Errorf("native vhost net server failed to start: %v", err)
	}

	return socketPath, server, nil
}

func supportsIoUring() bool {
	out, _ := exec.Command("qemu-img", "--help").CombinedOutput()
	return strings.Contains(string(out), "io_uring")
}
