package ebpf

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/cilium/ebpf"
)

// LoadEgressFilter uses the 'tc' command to load a compiled BPF object onto an interface
func LoadEgressFilter(interfaceName string, bpfObjPath string) error {
	// Add clsact qdisc; continue if it already exists
	qdiscAdded := false
	if err := exec.Command("tc", "qdisc", "add", "dev", interfaceName, "clsact").Run(); err == nil {
		qdiscAdded = true
	}
	
	// Attach BPF program to egress, replacing our specific filter if it exists
	cmd := exec.Command("tc", "filter", "replace", "dev", interfaceName, "egress", "prio", "1", "handle", "1", "bpf", "da", "obj", bpfObjPath, "sec", "tc")
	if err := cmd.Run(); err != nil {
		if qdiscAdded {
			exec.Command("tc", "qdisc", "del", "dev", interfaceName, "clsact").Run()
		}
		return fmt.Errorf("failed to attach bpf: %v", err)
	}
	return nil
}

// UpdateWhitelist updates the eBPF map. For the MVP we simulate this or use bpftool.
func UpdateWhitelist(domain string, ip string) error {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/whitelist_map", nil)
	if err != nil {
		return fmt.Errorf("failed to open pinned map: %v", err)
	}
	defer m.Close()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	ip4 := parsedIP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported")
	}

	// The key is the IPv4 address (4 bytes)
	var key [4]byte
	copy(key[:], ip4)
	val := uint32(1)

	if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update map: %v", err)
	}

	fmt.Printf("[eBPF] Whitelist updated: %s -> %s\n", domain, ip)
	return nil
}
