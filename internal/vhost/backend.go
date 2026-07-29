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

	cmd := exec.Command("qemu-storage-daemon",
		"--blockdev", fmt.Sprintf("driver=file,node-name=disk0,filename=%s,aio=io_uring", imagePath),
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
