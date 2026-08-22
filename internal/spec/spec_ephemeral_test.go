// spec_ephemeral_test.go — validation matrix for workspace.ephemeral
// (non-persistent sandboxes): the flag is accepted on its own, rejected in
// combination with the overlay lifecycle knobs it makes meaningless, and
// participates in the fingerprint contract.
package spec

import (
	"strings"
	"testing"
)

// ephemeralToml returns a minimal valid TOML with ephemeral on/off.
func ephemeralToml(on bool, extra string) string {
	flag := "false"
	if on {
		flag = "true"
	}
	return `version = 1
caller = "alice"
[runtime]
name = "t"
[workspace]
base_image = "rootfs.img"
init = "/init.sh"
ephemeral = ` + flag + `
` + extra
}

func TestLoadString_EphemeralAccepted(t *testing.T) {
	s, err := LoadString(ephemeralToml(true, ""))
	if err != nil {
		t.Fatalf("ephemeral spec rejected: %v", err)
	}
	if !s.Workspace.Ephemeral {
		t.Fatal("ephemeral not decoded")
	}
	// And off stays off (default).
	s, err = LoadString(ephemeralToml(false, ""))
	if err != nil {
		t.Fatalf("non-ephemeral spec rejected: %v", err)
	}
	if s.Workspace.Ephemeral {
		t.Fatal("ephemeral decoded true from false")
	}
}

func TestValidate_EphemeralCompactOnExitConflict(t *testing.T) {
	s := baseValid()
	s.Workspace.Ephemeral = true
	s.Workspace.CompactOnExit = true
	err := s.Validate()
	if err == nil {
		t.Fatal("ephemeral + compact_on_exit accepted")
	}
	if !strings.Contains(err.Error(), "compact_on_exit conflicts with workspace.ephemeral") {
		t.Fatalf("wrong error: %v", err)
	}
	// Same via LoadString (file-level path).
	_, err = LoadString(ephemeralToml(true, "compact_on_exit = true\n"))
	if err == nil || !strings.Contains(err.Error(), "compact_on_exit") {
		t.Fatalf("LoadString accepted ephemeral+compact: %v", err)
	}
}

func TestValidate_EphemeralOverlayConflict(t *testing.T) {
	s := baseValid()
	s.Workspace.Ephemeral = true
	s.Workspace.Overlay = "/var/lib/ov.qcow2"
	err := s.Validate()
	if err == nil {
		t.Fatal("ephemeral + overlay accepted")
	}
	if !strings.Contains(err.Error(), "workspace.overlay conflicts with workspace.ephemeral") {
		t.Fatalf("wrong error: %v", err)
	}
	_, err = LoadString(ephemeralToml(true, `overlay = "/tmp/ov.qcow2"`+"\n"))
	if err == nil || !strings.Contains(err.Error(), "overlay") {
		t.Fatalf("LoadString accepted ephemeral+overlay: %v", err)
	}
}

func TestValidate_EphemeralWithVolumesAllowed(t *testing.T) {
	// Declared persistent volumes are user intent: they stay attached and
	// preserved in ephemeral mode, so the combination is valid.
	s := baseValid()
	s.Workspace.Ephemeral = true
	s.Volumes = []VolumeMount{{Name: "data", Path: "/workspace"}}
	if err := s.Validate(); err != nil {
		t.Fatalf("ephemeral + volumes rejected: %v", err)
	}
}

func TestFingerprint_DistinguishesEphemeral(t *testing.T) {
	a := baseValid()
	a.Workspace.Ephemeral = false
	b := baseValid()
	b.Workspace.Ephemeral = true
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("ephemeral flag does not contribute to the fingerprint")
	}
}
