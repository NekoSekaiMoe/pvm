//go:build linux

package jail

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCapabilityDropHelperProcess runs in a subprocess: applies the real
// bounding-set drop, then verifies each dropped cap via PR_CAPBSET_READ
// (must read 0) and that kept caps survive (CAP_NET_ADMIN must read 1 when
// the test process holds it in its bounding set).
func TestCapabilityDropHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_CAP_DROP_HELPER") != "1" {
		return
	}
	if err := DropDangerousCapabilities(); err != nil {
		os.Exit(2)
	}
	for _, cap := range droppedBoundingCapabilities {
		ret, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(cap), 0, 0, 0)
		if err != nil {
			os.Exit(3)
		}
		if ret != 0 {
			os.Exit(4) // cap still in bounding set after drop
		}
	}
	// CAP_NET_ADMIN is deliberately kept (tap attach at runtime). If the
	// test environment's bounding set includes it, it must survive.
	ret, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, unix.CAP_NET_ADMIN, 0, 0, 0)
	if err == nil && ret != 1 {
		os.Exit(5) // NET_ADMIN was present but got dropped
	}
	os.Exit(0)
}

func TestCapabilityDropEnforcement(t *testing.T) {
	// Dropping bounding caps requires CAP_SETPCAP. All production paths
	// that reach DropDangerousCapabilities run as real root or as
	// namespaced root (both hold CAP_SETPCAP), but the plain test process
	// may be unprivileged — skip rather than fail there.
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("cannot read /proc/self/status: %v", err)
	}
	var capEff uint64
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "CapEff:"), "%x", &capEff); err != nil {
				t.Skipf("cannot parse CapEff: %v", err)
			}
		}
	}
	if capEff&(1<<unix.CAP_SETPCAP) == 0 {
		t.Skip("test process lacks CAP_SETPCAP (unprivileged host); drop path is exercised as root/namespaced root in CI")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestCapabilityDropHelperProcess$")
	cmd.Env = append(os.Environ(), "GO_WANT_CAP_DROP_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capability drop helper failed: %v, output: %s", err, string(out))
	}
}

// TestCapabilityDropKeepsRuntimeNeeds pins the split: dropped caps must never
// include the ones the UML monitor legitimately uses after exec.
func TestCapabilityDropKeepsRuntimeNeeds(t *testing.T) {
	kept := map[int]string{
		unix.CAP_NET_ADMIN:    "tap TUNSETIFF at runtime",
		unix.CAP_SYS_ADMIN:    "kept deliberately (breakout syscalls are seccomp-blocked)",
		unix.CAP_DAC_OVERRIDE: "volume files owned by other uids",
		unix.CAP_FOWNER:       "volume ownership quirks",
	}
	for cap, why := range kept {
		for _, dropped := range droppedBoundingCapabilities {
			if dropped == cap {
				t.Errorf("cap %d must NOT be dropped: %s", cap, why)
			}
		}
	}
}
