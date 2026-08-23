package container

import (
	"os"
	"testing"

	"uml-container/internal/jail"
)

func findVolume(vols []jail.VolumeMapping, guest string) *jail.VolumeMapping {
	for i := range vols {
		if vols[i].GuestPath == guest {
			return &vols[i]
		}
	}
	return nil
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestRouteLaunchThroughJail(t *testing.T) {
	t.Run("ubd0 rewritten to in-jail path with rw volume", func(t *testing.T) {
		args, vols := routeLaunchThroughJail(
			[]string{"init=/init.sh", "ubd0=/home/u/rootfs.img", "root=/dev/ubda"}, "")
		if !hasArg(args, "ubd0="+jailGuestRootfs) {
			t.Errorf("ubd0 not rewritten: %v", args)
		}
		v := findVolume(vols, jailGuestRootfs)
		if v == nil || v.HostPath != "/home/u/rootfs.img" || v.ReadOnly {
			t.Errorf("volume wrong: %+v (vols=%v)", v, vols)
		}
	})

	t.Run("ubd0r keeps device-level read-only", func(t *testing.T) {
		args, vols := routeLaunchThroughJail([]string{"ubd0r=/img/base.img"}, "")
		if !hasArg(args, "ubd0r="+jailGuestRootfs) {
			t.Errorf("ubd0r not rewritten: %v", args)
		}
		v := findVolume(vols, jailGuestRootfs)
		if v == nil || !v.ReadOnly || v.HostPath != "/img/base.img" {
			t.Errorf("volume wrong: %+v", v)
		}
	})

	t.Run("virtio vhost socket rewritten, id preserved", func(t *testing.T) {
		args, vols := routeLaunchThroughJail(
			[]string{"virtio_uml.device=/var/lib/uml-container/containers/t/vhost-blk.sock:1"}, "")
		if !hasArg(args, "virtio_uml.device="+jailGuestVhostSock+":1") {
			t.Errorf("virtio arg not rewritten: %v", args)
		}
		v := findVolume(vols, jailGuestVhostSock)
		if v == nil || v.HostPath != "/var/lib/uml-container/containers/t/vhost-blk.sock" {
			t.Errorf("volume wrong: %+v", v)
		}
	})

	t.Run("tap device binds /dev/net/tun", func(t *testing.T) {
		_, vols := routeLaunchThroughJail([]string{"init=/init.sh"}, "tap0")
		v := findVolume(vols, jailGuestTun)
		if v == nil || v.HostPath != "/dev/net/tun" {
			t.Errorf("tun volume missing: %v", vols)
		}
	})

	t.Run("no tap => no tun volume", func(t *testing.T) {
		_, vols := routeLaunchThroughJail([]string{"init=/init.sh"}, "")
		if findVolume(vols, jailGuestTun) != nil {
			t.Errorf("unexpected tun volume: %v", vols)
		}
	})

	t.Run("hostfs volumes get unique in-jail binds", func(t *testing.T) {
		args, vols := routeLaunchThroughJail(
			[]string{"hostfs_volume=/srv/a:/mnt/a", "hostfs_volume=/srv/b:/mnt/b"}, "")
		if !hasArg(args, "hostfs_volume=/volumes/v0:/mnt/a") ||
			!hasArg(args, "hostfs_volume=/volumes/v1:/mnt/b") {
			t.Errorf("hostfs args not rewritten: %v", args)
		}
		if findVolume(vols, "/volumes/v0") == nil || findVolume(vols, "/volumes/v1") == nil {
			t.Errorf("volume binds missing: %v", vols)
		}
	})

	t.Run("pathless args pass through unchanged", func(t *testing.T) {
		in := []string{"init=/init.sh", "mem=512M", "rw", "root=/dev/ubda"}
		args, vols := routeLaunchThroughJail(in, "")
		if len(vols) != 0 {
			t.Errorf("unexpected volumes: %v", vols)
		}
		for i, a := range in {
			if args[i] != a {
				t.Errorf("arg %d changed: %q -> %q", i, a, args[i])
			}
		}
	})
}

func TestVolumeAccessNote(t *testing.T) {
	const base, rng = 100000, 65536

	t.Run("degraded mode is a no-op", func(t *testing.T) {
		if note := volumeAccessNote("/nonexistent", 0, 0); note != "" {
			t.Errorf("uidRange=0 must never warn, got %q", note)
		}
	})

	t.Run("range-owned volume is silent", func(t *testing.T) {
		dir := t.TempDir()
		if os.Geteuid() != 0 {
			t.Skip("chown requires root")
		}
		if err := os.Chown(dir, base+7, base+7); err != nil {
			t.Fatal(err)
		}
		if note := volumeAccessNote(dir, base, rng); note != "" {
			t.Errorf("range-owned volume warned: %q", note)
		}
	})

	t.Run("world-accessible foreign volume is silent", func(t *testing.T) {
		dir := t.TempDir() // 0700 by default...
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if note := volumeAccessNote(dir, base, rng); note != "" {
			t.Errorf("world-traversable volume warned: %q", note)
		}
	})

	t.Run("locked-down foreign volume warns", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		note := volumeAccessNote(dir, base, rng)
		if note == "" {
			t.Error("expected EACCES warning for foreign 0700 volume")
		}
	})

	t.Run("missing path warns", func(t *testing.T) {
		if note := volumeAccessNote("/nonexistent/path/xyz", base, rng); note == "" {
			t.Error("expected stat-failure warning")
		}
	})
}
