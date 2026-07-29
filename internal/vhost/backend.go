package vhost

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
	"os"
)

// StartStorageDaemon starts qemu-storage-daemon to provide a vhost-user-blk socket.
// Requires qemu-storage-daemon installed on the host.
func StartStorageDaemon(containerID string, imagePath string) (string, *exec.Cmd, error) {
	dir := filepath.Join("/var/lib/uml-container/containers", containerID)
	os.MkdirAll(dir, 0755)
	socketPath := filepath.Join(dir, "vhost-blk.sock")
	
	// If it already exists, remove it
	os.Remove(socketPath)

	cmd := exec.Command("qemu-storage-daemon",
		"--blockdev", fmt.Sprintf("driver=file,node-name=disk0,filename=%s", imagePath),
		"--blockdev", "driver=raw,node-name=raw0,file=disk0",
		"--export", fmt.Sprintf("type=vhost-user-blk,id=export0,node-name=raw0,addr.type=unix,addr.path=%s,writable=on", socketPath),
	)
	
	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("failed to start qemu-storage-daemon: %v", err)
	}
	
	// Wait for socket to be created
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	return socketPath, cmd, nil
}
