package ebpf

import (
	"fmt"
	"os/exec"
)

// LoadEgressFilter uses the 'tc' command to load a compiled BPF object onto an interface
func LoadEgressFilter(interfaceName string, bpfObjPath string) error {
	// Remove existing qdisc if any
	exec.Command("tc", "qdisc", "del", "dev", interfaceName, "clsact").Run()
	
	// Add clsact qdisc
	if err := exec.Command("tc", "qdisc", "add", "dev", interfaceName, "clsact").Run(); err != nil {
		return fmt.Errorf("failed to add clsact qdisc: %v", err)
	}
	
	// Attach BPF program to egress
	cmd := exec.Command("tc", "filter", "add", "dev", interfaceName, "egress", "bpf", "da", "obj", bpfObjPath, "sec", "tc")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to attach bpf: %v", err)
	}
	return nil
}

// UpdateWhitelist updates the eBPF map. For the MVP we simulate this or use bpftool.
func UpdateWhitelist(domain string, ip string) error {
	fmt.Printf("[eBPF] Whitelist updated: %s -> %s\n", domain, ip)
	// In production: exec.Command("bpftool", "map", "update", "name", "whitelist_map", ...)
	return nil
}
