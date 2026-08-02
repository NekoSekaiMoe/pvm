// Package vhost wires up virtio devices to UML via the vhost-user protocol.
//
// Today the only backend is qemu-storage-daemon for virtio-blk: PVM launches it
// as a subprocess and points UML's virtio_uml.device=<socket>:2 at the unix
// socket it serves. A native Go vhost-user server previously lived here but
// was removed — it never reached a working state, and qemu-storage-daemon is
// the mature reference implementation.
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

// Virtio device IDs as defined in the kernel's virtio_ids.h. Used by the UML
// virtio_uml driver command line: virtio_uml.device=<socket>:<virtio_id>.
const (
	VirtioIDBlock = 2
)

// StartStorageDaemon starts qemu-storage-daemon to provide a vhost-user-blk
// socket and returns the socket path plus the running daemon process (the
// caller is responsible for killing it on teardown). Requires
// qemu-storage-daemon installed on the host; image format is inferred from the
// path extension (.qcow2 -> qcow2, otherwise raw).
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

	// imagePath is interpolated directly into qemu-storage-daemon args; a comma
	// would inject a new option, so reject it before exec.
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

	// Wait for socket to be created (the daemon takes a moment to set up the
	// export). Bail early if the daemon dies before publishing the socket.
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

// supportsIoUring reports whether the installed qemu-img advertises io_uring
// support, so StartStorageDaemon can pick the faster AIO backend when present.
func supportsIoUring() bool {
	out, _ := exec.Command("qemu-img", "--help").CombinedOutput()
	return strings.Contains(string(out), "io_uring")
}
