// Package vhost wires up virtio devices to UML via the vhost-user protocol.
//
// The default backend is the in-process Go vhost-user-blk server
// (internal/vhost/vu) backed by the pure-Go qcow2/raw storage
// (internal/cow) — no qemu-storage-daemon subprocess needed. Setting
// PVM_VHOST_BACKEND=qemu falls back to launching qemu-storage-daemon as a
// subprocess (escape hatch for A/B debugging against the reference).
//
// UML connects via virtio_uml.device=<socket>:<virtio_id>.
package vhost

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"uml-container/internal/cow"
	"uml-container/internal/state"
	"uml-container/internal/vhost/vu"
)

// Virtio device IDs as defined in the kernel's virtio_ids.h. Used by the UML
// virtio_uml driver command line: virtio_uml.device=<socket>:<virtio_id>.
const (
	VirtioIDBlock = 2
)

// StartBlk starts a vhost-user-blk backend for imagePath (raw or qcow2,
// sniffed by content) serving on a unix socket under the container's state
// dir. The returned closer tears the backend down (server or subprocess);
// callers must also remove the socket path.
func StartBlk(containerID string, imagePath string) (string, io.Closer, error) {
	if os.Getenv("PVM_VHOST_BACKEND") == "qemu" {
		return startQemuDaemon(containerID, imagePath)
	}
	return startGoServer(containerID, imagePath)
}

// startGoServer runs the pure-Go vhost-user-blk server in-process.
func startGoServer(containerID string, imagePath string) (string, io.Closer, error) {
	socketPath, err := prepareSocket(containerID)
	if err != nil {
		return "", nil, err
	}
	be, err := cow.OpenWritable(imagePath)
	if err != nil {
		return "", nil, fmt.Errorf("vhost: open image: %w", err)
	}
	dev, err := vu.NewBlkDev(be, false)
	if err != nil {
		be.Close()
		return "", nil, fmt.Errorf("vhost: blk device: %w", err)
	}
	srv, err := vu.Serve(socketPath, dev)
	if err != nil {
		be.Close()
		return "", nil, fmt.Errorf("vhost: serve: %w", err)
	}
	return socketPath, &goBackend{srv: srv, be: be}, nil
}

type goBackend struct {
	srv *vu.Server
	be  cow.WritableBackend
}

func (g *goBackend) Close() error {
	err := g.srv.Close()
	if berr := g.be.Close(); err == nil {
		err = berr
	}
	return err
}

// prepareSocket creates the container state dir and returns the socket path.
func prepareSocket(containerID string) (string, error) {
	dir, err := state.ContainerDir(containerID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create dir: %v", err)
	}
	return filepath.Join(dir, "vhost-blk.sock"), nil
}

// qemuDaemon adapts a qemu-storage-daemon subprocess to io.Closer.
type qemuDaemon struct {
	cmd *exec.Cmd
}

func (q *qemuDaemon) Close() error {
	if q.cmd.Process == nil {
		return nil
	}
	_ = q.cmd.Process.Kill()
	_ = q.cmd.Wait()
	return nil
}

// startQemuDaemon launches qemu-storage-daemon as a subprocess serving a
// vhost-user-blk socket (reference backend; requires qemu installed).
func startQemuDaemon(containerID string, imagePath string) (string, io.Closer, error) {
	socketPath, err := prepareSocket(containerID)
	if err != nil {
		return "", nil, err
	}
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
				break // process dead
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

	return socketPath, &qemuDaemon{cmd: cmd}, nil
}

// supportsIoUring reports whether the installed qemu-img advertises io_uring
// support, so the qemu fallback can pick the faster AIO backend when present.
func supportsIoUring() bool {
	out, _ := exec.Command("qemu-img", "--help").CombinedOutput()
	return strings.Contains(string(out), "io_uring")
}
