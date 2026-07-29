package network

import (
	"fmt"
	"os/exec"
)

// SetupBridge creates a NAT bridge for UML containers
func SetupBridge(bridgeName string, tapName string) error {
	// Create bridge if not exists
	exec.Command("ip", "link", "add", "name", bridgeName, "type", "bridge").Run()
	exec.Command("ip", "link", "set", bridgeName, "up").Run()

	// Assign IP to bridge (simple hardcoded for MVP)
	exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", bridgeName).Run()

	// Add tap to bridge
	if err := exec.Command("ip", "link", "set", tapName, "master", bridgeName).Run(); err != nil {
		return fmt.Errorf("failed to attach tap to bridge: %v", err)
	}

	// Setup NAT (iptables)
	exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "!", "-o", bridgeName, "-j", "MASQUERADE").Run()
	// Enable IP forwarding
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	return nil
}
