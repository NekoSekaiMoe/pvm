//go:build linux

package jail

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// ConfigureProcessIsolation decorates the exec.Cmd with death-signals and isolation attributes.
func ConfigureProcessIsolation(cmd *exec.Cmd, j *JailEnvironment) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Always send SIGKILL to the UML child if the parent manager exits
	cmd.SysProcAttr.Pdeathsig = unix.SIGKILL

	caps := DetectHostCapabilities()
	// If UserNS and MountNS are available on the host, enable namespace isolation
	if caps.HasUserNS && caps.HasMountNS && j != nil {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS
		// Map current UID/GID to UID 0 inside container for rootless execution
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: unix.Getuid(), Size: 1},
		}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: unix.Getgid(), Size: 1},
		}
	}

	return nil
}
