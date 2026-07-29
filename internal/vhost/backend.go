package vhost

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"os"

	"uml-container/internal/state"
)

// StartStorageDaemon starts qemu-storage-daemon to provide a vhost-user-blk socket.
// Requires qemu-storage-daemon installed on the host.
func StartStorageDaemon(containerID string, imagePath string) (string, *exec.Cmd, error) {
	dir := state.ContainerDir(containerID)
	os.MkdirAll(dir, 0755)
	socketPath := filepath.Join(dir, "vhost-blk.sock")
	
	// If it already exists, remove it
	os.Remove(socketPath)

	formatDriver := "raw"
	if filepath.Ext(imagePath) == ".qcow2" {
		formatDriver = "qcow2"
	}

	if strings.Contains(imagePath, ",") {
		return "", nil, fmt.Errorf("invalid imagePath: cannot contain comma")
	}

	cmd := exec.Command("qemu-storage-daemon",
		"--blockdev", fmt.Sprintf("driver=file,node-name=disk0,filename=%s", imagePath),
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
		time.Sleep(100 * time.Millisecond)
	}
	
	if !found {
		return "", nil, fmt.Errorf("timeout waiting for socket to be created: %s", socketPath)
	}
	
	return socketPath, cmd, nil
}
