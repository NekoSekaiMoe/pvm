package network

// Unit tests for the P2 bridgeless tc dataplane helpers. The attach/detach
// paths need root + bpffs + clsact, so they are covered here only up to the
// first privileged syscall (typed error, no-root tolerant) and by the
// root-guarded leg of tests/35_test_tc_ebpf_dataplane.sh.

import (
	"errors"
	"os"
	"strings"
	"testing"
	"unsafe"
)

func TestPortBaseForTask(t *testing.T) {
	seen := map[uint32]string{}
	for _, id := range []string{"task-a", "task-b", "tc35t-task", "x", "task-001", "sandbox_9f"} {
		base := PortBaseForTask(id)
		if base < snatPortBaseMin || base >= snatPortBaseMin+snatPortBaseSpan {
			t.Fatalf("PortBaseForTask(%q) = %d outside [%d, %d)", id, base, snatPortBaseMin, snatPortBaseMin+snatPortBaseSpan)
		}
		if (base-snatPortBaseMin)%snatPortWindow != 0 {
			t.Fatalf("PortBaseForTask(%q) = %d not on a %d-port block above %d", id, base, snatPortWindow, snatPortBaseMin)
		}
		if other, dup := seen[base]; dup {
			t.Logf("note: %q and %q share window base %d (allowed; in-window retry handles it)", other, id, base)
		}
		seen[base] = id
		// Deterministic across calls.
		if again := PortBaseForTask(id); again != base {
			t.Fatalf("PortBaseForTask(%q) not deterministic: %d then %d", id, base, again)
		}
	}
}

// TestSessionABISize pins the Go/kernel ABI of the NAT maps: the bpf2go
// generated structs mirror the C structs in bpf/tap_dataplane.c via BTF;
// these sizes/offsets are what the pinned maps carry on disk.
func TestSessionABISize(t *testing.T) {
	if got := unsafe.Sizeof(tapdpSessionKey{}); got != 16 {
		t.Fatalf("session key size = %d, want 16", got)
	}
	if got := unsafe.Sizeof(tapdpSessionValue{}); got != 32 {
		t.Fatalf("session value size = %d, want 32", got)
	}
	if got := unsafe.Sizeof(tapdpGwTarget{}); got != 16 {
		t.Fatalf("gw target size = %d, want 16", got)
	}
	// Field packing of the reply-5-tuple key (network-order fields).
	k := tapdpSessionKey{}
	if unsafe.Offsetof(k.RemoteIp) != 0 || unsafe.Offsetof(k.NatIp) != 4 ||
		unsafe.Offsetof(k.RemotePort) != 8 || unsafe.Offsetof(k.NatPort) != 10 ||
		unsafe.Offsetof(k.Proto) != 12 {
		t.Fatal("session key field packing drifted from the C struct")
	}
	v := tapdpSessionValue{}
	if unsafe.Offsetof(v.GuestIp) != 0 || unsafe.Offsetof(v.GuestPort) != 4 ||
		unsafe.Offsetof(v.TapIfindex) != 8 || unsafe.Offsetof(v.GuestMac) != 12 ||
		unsafe.Offsetof(v.GwMac) != 18 || unsafe.Offsetof(v.LastSeenNs) != 24 {
		t.Fatal("session value field packing drifted from the C struct")
	}
}

func TestAttachTapDataplaneInvalidTaskID(t *testing.T) {
	// Path-unsafe task ids must be rejected BEFORE any host mutation
	// (pvm-gw setup, bpffs) — same contract as WhitelistPinPath.
	for _, id := range []string{"../escape", "a/b", "with space", "dot.dot"} {
		_, err := AttachTapDataplane(id, "tap_x", "")
		var derr *TapDataplaneError
		if !errors.As(err, &derr) {
			t.Fatalf("AttachTapDataplane(%q): want *TapDataplaneError, got %v", id, err)
		}
		if derr.Op != "validate" {
			t.Fatalf("AttachTapDataplane(%q): op = %q, want validate", id, derr.Op)
		}
	}
	if _, err := AttachTapDataplane("ok-task", "", ""); err == nil {
		t.Fatal("empty tap name accepted")
	}
}

func TestAttachTapDataplaneNoRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: attach may legitimately succeed and mutate host state")
	}
	_, err := AttachTapDataplane("dp-unit-test", "tap_dpunit", "")
	var derr *TapDataplaneError
	if !errors.As(err, &derr) {
		t.Fatalf("want *TapDataplaneError without root, got: %v", err)
	}
	// Without CAP_NET_ADMIN the shared gateway device setup is the first
	// privileged step and must fail; every earlier step is pure validation.
	if derr.Op != "gw" && derr.Op != "load" {
		t.Fatalf("unexpected first failing op without root: %q (%v)", derr.Op, err)
	}
	if !strings.Contains(derr.Tap, "tap_dpunit") {
		t.Fatalf("typed error lost the tap name: %v", derr)
	}
}

func TestDetachTapDataplaneUnknown(t *testing.T) {
	// No registry entry, no pin dir: idempotent no-op.
	if err := DetachTapDataplane("dp-never-attached"); err != nil {
		t.Fatalf("detach of unknown task: %v", err)
	}
}

func TestDataplaneStatusEmpty(t *testing.T) {
	if got := DataplaneStatus(); len(got) != 0 {
		t.Fatalf("DataplaneStatus with no attachments: %v", got)
	}
	if _, ok := DataplaneStatusFor("nobody"); ok {
		t.Fatal("DataplaneStatusFor found a phantom task")
	}
}

func TestGwDeviceStatusUnprivileged(t *testing.T) {
	// Read-only netlink: must work without root and report the posture
	// keys whether or not pvm-gw exists on this host.
	st := GwDeviceStatus()
	if st["name"] != gwDeviceName {
		t.Fatalf("name = %v", st["name"])
	}
	if _, ok := st["exists"].(bool); !ok {
		t.Fatalf("exists missing/not bool: %v", st)
	}
}

func TestSweepOnceNilMap(t *testing.T) {
	// A half-initialized dataplane must not panic the sweeper.
	d := &TapDataplane{}
	if got := d.sweepOnce(0); got != 0 {
		t.Fatalf("sweepOnce on nil sessions = %d", got)
	}
}
