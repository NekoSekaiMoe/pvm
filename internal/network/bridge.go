package network

import (
	"fmt"
	"os/exec"
)

// SetupBridge creates a NAT bridge
func SetupBridge(bridgeName string, tapName string, gatewayIP string) error {
	exec.Command("ip", "link", "add", "name", bridgeName, "type", "bridge").Run()
	exec.Command("ip", "link", "set", bridgeName, "up").Run()

	exec.Command("ip", "addr", "add", gatewayIP, "dev", bridgeName).Run()

	if tapName != "" {
		exec.Command("ip", "link", "set", tapName, "master", bridgeName).Run()
	}

	// Setup NAT (iptables) for the subnet (e.g. 10.0.0.0/24 from gateway 10.0.0.1/24)
	exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "!", "-o", bridgeName, "-j", "MASQUERADE").Run()
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	return nil
}

// DeleteBridge removes a bridge
func DeleteBridge(bridgeName string) error {
	exec.Command("ip", "link", "set", bridgeName, "down").Run()
	if err := exec.Command("ip", "link", "delete", "name", bridgeName, "type", "bridge").Run(); err != nil {
		return fmt.Errorf("failed to delete bridge %s: %v", bridgeName, err)
	}
	return nil
}
