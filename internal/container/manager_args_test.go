package container

import (
	"context"
	"strings"
	"testing"

	"uml-container/internal/config"
	"uml-container/internal/spec"
)

// TestValidateKernelField pins the character-set contract for values
// interpolated into the UML kernel command line: no whitespace (would split
// the argument) and no comma (would inject options into composite
// parameters like vec0=... or virtio_uml.device=...).
func TestValidateKernelField(t *testing.T) {
	cases := []struct {
		name string
		val  string
		ok   bool
	}{
		{"plain", "/init.sh", true},
		{"tap name", "tap0", true},
		{"socket path", "/run/c/vhost-blk.sock", true},
		{"host:port", "127.0.0.1:8080", true},
		{"empty", "", false},
		{"space", "a b", false},
		{"tab", "a\tb", false},
		{"newline", "a\nb", false},
		{"comma", "a,b", false},
		{"injection via comma", "tap0,depth=1,gro=0", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateKernelField("field", c.val)
			if c.ok && err != nil {
				t.Fatalf("validateKernelField(%q) = %v, want nil", c.val, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("validateKernelField(%q) = nil, want error", c.val)
			}
		})
	}
}

// TestValidateRootfs pins the extra rootfs constraints: absolute path, no
// '..' element, plus the base character-set rules.
func TestValidateRootfs(t *testing.T) {
	cases := []struct {
		name string
		val  string
		ok   bool
	}{
		{"absolute", "/var/lib/uml/rootfs.img", true},
		{"relative", "rootfs.img", false},
		{"dotdot traversal", "/var/lib/../etc/passwd", false},
		{"dotdot leading", "../var/lib/img", false},
		{"dotdot hidden name ok", "/var/lib/x..y/img", true}, // ".." only as full element is rejected
		{"space", "/var/li b/img", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateRootfs(c.val)
			if c.ok && err != nil {
				t.Fatalf("validateRootfs(%q) = %v, want nil", c.val, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("validateRootfs(%q) = nil, want error", c.val)
			}
		})
	}
}

// TestValidateMemory pins the canonical-size whitelist for mem=.
func TestValidateMemory(t *testing.T) {
	for _, ok := range []string{"268435456", "512M", "512m", "1G", "2k"} {
		if err := validateMemory(ok); err != nil {
			t.Errorf("validateMemory(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "512 MB", "512Mi", "1,5G", "a b", "512M x", "0x100"} {
		if err := validateMemory(bad); err == nil {
			t.Errorf("validateMemory(%q) = nil, want error", bad)
		}
	}
}

// TestBuildLegacyArgs_RejectsInjection drives the legacy arg builder with
// hostile field values; every case must be rejected before any process is
// spawned.
func TestBuildLegacyArgs_RejectsInjection(t *testing.T) {
	base := config.ContainerConfig{
		ID: "c1", Kernel: "/kernel", Rootfs: "/rootfs.img",
		Memory: "512M", Init: "/init.sh",
	}
	cases := []struct {
		name string
		mut  func(*config.ContainerConfig)
	}{
		{"init comma", func(c *config.ContainerConfig) { c.Init = "/init.sh,con=null" }},
		{"init space", func(c *config.ContainerConfig) { c.Init = "/init sh" }},
		{"memory bad", func(c *config.ContainerConfig) { c.Memory = "512M rw" }},
		{"tap comma", func(c *config.ContainerConfig) { c.NetworkTap = "tap0,depth=1" }},
		{"rootfs relative", func(c *config.ContainerConfig) { c.Rootfs = "rootfs.img" }},
		{"vhost socket comma", func(c *config.ContainerConfig) {
			c.UseVirtio = true
			c.VhostUserSocket = "/s,virtio=x"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base
			c.mut(&cfg)
			if _, err := buildLegacyArgs(context.Background(), &cfg); err == nil {
				t.Fatalf("buildLegacyArgs accepted hostile config %+v", cfg)
			}
		})
	}
}

// TestBuildLegacyArgs_AcceptsLegitFixture keeps the honest path working:
// /init.sh, tap0, absolute rootfs, canonical memory.
func TestBuildLegacyArgs_AcceptsLegitFixture(t *testing.T) {
	cfg := config.ContainerConfig{
		ID: "c1", Kernel: "/kernel", Rootfs: "/var/lib/uml/rootfs.img",
		Memory: "512M", Init: "/init.sh", NetworkTap: "tap0",
	}
	args, err := buildLegacyArgs(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("buildLegacyArgs: %v", err)
	}
	joined := strings.Join(args, "\n")
	for _, want := range []string{"init=/init.sh", "mem=512M", "ubd0=/var/lib/uml/rootfs.img", "ifname=tap0"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q:\n%s", want, joined)
		}
	}
}

// TestBuildTaskArgs_RejectsInjection covers the TaskSpec-driven builder,
// including the composite hostfs_volume=<host>:<guest> argument: commas in
// either side must be rejected while the ':' separator stays legal.
func TestBuildTaskArgs_RejectsInjection(t *testing.T) {
	validSpec := func() *spec.TaskSpec {
		return &spec.TaskSpec{
			Workspace: spec.WorkspaceSpec{Init: "/init.sh"},
			Runtime:   spec.RuntimeSpec{Memory: "512M"},
			Kernel:    spec.KernelSpec{UseVhostBlk: true},
		}
	}
	cases := []struct {
		name       string
		spec       *spec.TaskSpec
		vhostSock  string
		rootfs     string
		egressAddr string
		volumeArgs []string
	}{
		{"tap comma", func() *spec.TaskSpec {
			s := validSpec()
			s.Network = spec.NetworkSpec{Enabled: true, TAP: "tap0,depth=1"}
			return s
		}(), "", "/overlay.img", "", nil},
		{"rootfs relative", validSpec(), "", "overlay.img", "", nil},
		{"memory bad", func() *spec.TaskSpec {
			s := validSpec()
			s.Runtime.Memory = "512M extra"
			return s
		}(), "", "/overlay.img", "", nil},
		{"vhost sock comma", validSpec(), "/s,x", "/overlay.img", "", nil},
		{"egress comma", validSpec(), "", "/overlay.img", "1.2.3.4:8080,extra", nil},
		{"volume arg no colon", validSpec(), "", "/overlay.img", "", []string{"just-a-path"}},
		{"volume host comma", validSpec(), "", "/overlay.img", "", []string{"/ho,st:/guest"}},
		{"volume guest comma", validSpec(), "", "/overlay.img", "", []string{"/host:/gue,st"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildTaskArgs(c.spec, c.vhostSock, c.rootfs, c.egressAddr, c.volumeArgs); err == nil {
				t.Fatalf("buildTaskArgs accepted hostile input %q", c.name)
			}
		})
	}
}

// TestBuildTaskArgs_AcceptsLegitFixture keeps the TaskSpec path honest.
func TestBuildTaskArgs_AcceptsLegitFixture(t *testing.T) {
	s := &spec.TaskSpec{
		Workspace: spec.WorkspaceSpec{Init: "/init.sh"},
		Runtime:   spec.RuntimeSpec{Memory: "1G"},
		Kernel:    spec.KernelSpec{UseVhostBlk: true},
		Network:   spec.NetworkSpec{Enabled: true, TAP: "tap0"},
	}
	args, err := buildTaskArgs(s, "/run/x/vhost-blk.sock", "/overlays/t1.img", "10.0.0.1:3128",
		[]string{"/host/share:/mnt/share"})
	if err != nil {
		t.Fatalf("buildTaskArgs: %v", err)
	}
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		"init=/init.sh", "mem=1G", "virtio_uml.device=/run/x/vhost-blk.sock:2",
		"ifname=tap0", "egress_proxy=10.0.0.1:3128", "hostfs_volume=/host/share:/mnt/share",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q:\n%s", want, joined)
		}
	}
}
