package container

import (
	"fmt"
	"os"
	"strings"
	"syscall"

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

// volumeAccessNote preflights a hostfs volume for the rootless jail and
// returns a human-readable warning, or "" when access should work.
//
// The namespaced monitor accesses volume files with fixed host creds (host
// uid uidBase+k for guest uid k). Files owned INSIDE the container's
// allocated range appear to the guest with the right owner (host uidBase+k
// maps to guest k through the userns map) and pass DAC; everything else
// falls back to the world/other permission bits.
//
// Why not idmapped mounts: a mount idmap is a single injective mapping and
// the monitor's host creds are fixed, so a FOREIGN owner uid can never be
// mapped to both "guest sees uid k" and "monitor creds match owner" at the
// same time — idmapped mounts are a no-op for this topology (the
// k8s/podman idmapped-volume practice only works because their volumes are
// already subuid-range-owned, which is exactly the case that needs
// nothing). The contract therefore is: volumes are range-owned or
// world-accessible.
func volumeAccessNote(hostPath string, uidBase, uidRange uint32, readOnly bool) string {
	if uidRange == 0 {
		return ""
	}
	fi, err := os.Stat(hostPath)
	if err != nil {
		return fmt.Sprintf("cannot stat volume host path: %v", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	if st.Uid >= uidBase && st.Uid < uidBase+uidRange {
		return "" // owned inside the container's range: guest sees the right owner
	}
	need := os.FileMode(0004) // other-read
	if fi.IsDir() {
		need = 0005 // other r-x to traverse
	}
	if !readOnly {
		// rw volumes: the namespaced monitor WRITES with its "other"
		// creds too — without o+w the preflight would pass and the guest
		// would hit EACCES on first write with no warning recorded.
		need |= 0002
	}
	if fi.Mode().Perm()&need == need {
		return "" // world-accessible enough for the monitor's "other" creds
	}
	return fmt.Sprintf("owned by host uid %d outside the container uid range [%d,%d) and not world-accessible (mode %04o); "+
		"the rootless monitor will get EACCES — chown -R %d:%d the volume or loosen its permission bits",
		st.Uid, uidBase, uidBase+uidRange, fi.Mode().Perm(), uidBase, uidBase)
}

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

// grantMonitorImageAccess widens rw rootfs images so the namespaced monitor
// can open them (see jail.GrantMonitorRW for why the in-jail bind alone is
// not enough — the inode's DAC is checked against the monitor's fixed host
// creds). A grant failure is NOT fatal: the guest still boots, just with a
// read-only rootfs, so surface it loudly and let the caller decide.
func grantMonitorImageAccess(jailEnv *jail.JailEnvironment, vols []jail.VolumeMapping, uidBase uint32) {
	if uidBase == 0 {
		return // degraded leg: the monitor is real root, no DAC gap to bridge
	}
	for _, v := range vols {
		if v.GuestPath != jailGuestRootfs || v.ReadOnly {
			continue
		}
		if err := jailEnv.GrantMonitorRW(v.HostPath, uidBase, uidBase); err != nil {
			fmt.Printf("Warning: cannot grant the rootless monitor rw access to %s: %v "+
				"(guest rootfs will be READ-ONLY)\n", v.HostPath, err)
		}
	}
}
