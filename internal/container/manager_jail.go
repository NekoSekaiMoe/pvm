package container

import (
	"fmt"
	"strings"

	"uml-container/internal/jail"
)

// In-jail bind-mount targets. The jail's pivot_root gives the UML kernel a
// minimal rootfs; every host path the kernel must open at runtime is bound
// in at one of these fixed locations and the kernel command line is
// rewritten to match. SetupJail pre-creates the parent dirs (images/,
// sockets/, volumes/, dev/) and the jail helper adds each volume's
// GuestPath to the Landlock allowlist.
const (
	jailGuestRootfs    = "/images/rootfs.img"
	jailGuestVhostSock = "/sockets/vhost-blk.sock"
	jailGuestTun       = "/dev/net/tun"
)

// routeLaunchThroughJail rewrites kernel args so that every host path the
// kernel must open points at its in-jail bind mount, returning the volume
// mappings that make those paths visible inside the jail.
//
// Without this the jailed kernel dies exactly where CI run 88449954750 did:
// ubd0=/home/runner/... does not exist past the pivot_root, so the ubd
// driver fails ("Couldn't determine size of device's file") and the boot
// panics with "VFS: Unable to mount root fs". The same applies to the
// vhost-user socket (virtio_uml.device) and hostfs volume roots.
//
// tapDevice non-empty additionally binds /dev/net/tun: the vec tap
// transport opens it for TUNSETIFF at device-init time.
//
// Must only be applied when the launch will actually enter the jail
// (JailEnvironment.IsolationActive); otherwise the kernel keeps the host
// filesystem view and the original host paths are the correct ones.
func routeLaunchThroughJail(args []string, tapDevice string) ([]string, []jail.VolumeMapping) {
	var vols []jail.VolumeMapping
	out := make([]string, 0, len(args))
	volIdx := 0
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "ubd0="):
			host := strings.TrimPrefix(a, "ubd0=")
			vols = append(vols, jail.VolumeMapping{HostPath: host, GuestPath: jailGuestRootfs})
			a = "ubd0=" + jailGuestRootfs
		case strings.HasPrefix(a, "ubd0r="):
			host := strings.TrimPrefix(a, "ubd0r=")
			vols = append(vols, jail.VolumeMapping{HostPath: host, GuestPath: jailGuestRootfs, ReadOnly: true})
			a = "ubd0r=" + jailGuestRootfs
		case strings.HasPrefix(a, "virtio_uml.device="):
			// Value is "<socket path>:<virtio id>" — split at the LAST
			// colon so socket paths are never mis-parsed (paths are
			// validated comma/whitespace-free upstream; the id is numeric).
			rest := strings.TrimPrefix(a, "virtio_uml.device=")
			if idx := strings.LastIndex(rest, ":"); idx > 0 {
				vols = append(vols, jail.VolumeMapping{HostPath: rest[:idx], GuestPath: jailGuestVhostSock})
				a = "virtio_uml.device=" + jailGuestVhostSock + rest[idx:]
			}
		case strings.HasPrefix(a, "hostfs_volume="):
			// Value is "<host dir>:<guest mountpoint>"; the kernel opens
			// the host dir at mount time, so it needs the in-jail view.
			rest := strings.TrimPrefix(a, "hostfs_volume=")
			if host, guest, found := strings.Cut(rest, ":"); found && host != "" {
				bind := fmt.Sprintf("/volumes/v%d", volIdx)
				volIdx++
				vols = append(vols, jail.VolumeMapping{HostPath: host, GuestPath: bind})
				a = "hostfs_volume=" + bind + ":" + guest
			}
		}
		out = append(out, a)
	}
	if tapDevice != "" {
		vols = append(vols, jail.VolumeMapping{HostPath: jailGuestTun, GuestPath: jailGuestTun})
	}
	return out, vols
}
