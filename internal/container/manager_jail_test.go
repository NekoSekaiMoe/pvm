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

	// Range ownership requires chown, so it stays a separate root-gated
	// subtest; everything else is a permission-bits decision table.
	t.Run("range-owned volume is silent", func(t *testing.T) {
		dir := t.TempDir()
		if os.Geteuid() != 0 {
			t.Skip("chown requires root")
		}
		if err := os.Chown(dir, base+7, base+7); err != nil {
			t.Fatal(err)
		}
		if note := volumeAccessNote(dir, base, rng, false); note != "" {
			t.Errorf("range-owned volume warned: %q", note)
		}
	})

	dirWithMode := func(mode os.FileMode) func(t *testing.T) string {
		return func(t *testing.T) string {
			dir := t.TempDir() // 0700 by default
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			return dir
		}
	}
	staticPath := func(p string) func(t *testing.T) string {
		return func(t *testing.T) string { return p }
	}

	cases := []struct {
		name     string
		setup    func(t *testing.T) string
		uidRange uint32
		readOnly bool
		wantNote bool
	}{
		{"degraded mode is a no-op", staticPath("/nonexistent"), 0, false, false},
		{"missing path warns", staticPath("/nonexistent/path/xyz"), rng, true, true},
		{"locked-down foreign volume warns", dirWithMode(0700), rng, false, true},
		{"world-traversable ro volume is silent", dirWithMode(0755), rng, true, false},
		{"rw volume without other-write warns", dirWithMode(0755), rng, false, true},
		{"world-writable rw volume is silent", dirWithMode(0757), rng, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			note := volumeAccessNote(c.setup(t), base, c.uidRange, c.readOnly)
			if c.wantNote && note == "" {
				t.Error("expected a warning, got none")
			}
			if !c.wantNote && note != "" {
				t.Errorf("unexpected warning: %q", note)
			}
		})
	}
}
