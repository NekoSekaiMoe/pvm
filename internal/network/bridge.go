package network

import (
	"fmt"
	"os/exec"
)

// SetupBridge creates a NAT bridge
func SetupBridge(bridgeName string, tapName string, gatewayIP string) error {
	if err := exec.Command("ip", "link", "add", "name", bridgeName, "type", "bridge").Run(); err != nil {
		return fmt.Errorf("failed to add bridge %s: %v", bridgeName, err)
	}
	if err := exec.Command("ip", "link", "set", bridgeName, "up").Run(); err != nil {
		return fmt.Errorf("failed to set bridge %s up: %v", bridgeName, err)
	}

	if err := exec.Command("ip", "addr", "add", gatewayIP, "dev", bridgeName).Run(); err != nil {
		return fmt.Errorf("failed to add ip to bridge %s: %v", bridgeName, err)
	}

	if tapName != "" {
		if err := exec.Command("ip", "link", "set", tapName, "master", bridgeName).Run(); err != nil {
			return fmt.Errorf("failed to set tap %s master %s: %v", tapName, bridgeName, err)
		}
	}

	// Setup NAT (iptables) for the subnet (e.g. 10.0.0.0/24 from gateway 10.0.0.1/24)
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "!", "-o", bridgeName, "-j", "MASQUERADE").Run(); err != nil {
		return fmt.Errorf("failed to setup iptables NAT: %v", err)
	}
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("failed to enable ip_forward: %v", err)
	}

	return nil
}

// SetupQoS sets bandwidth limits on a tap interface to prevent abuse
func SetupQoS(tapName string, rate string) error {
	// e.g. rate="10mbit"
	// tc qdisc add dev tap0 root tbf rate 10mbit burst 32kbit latency 400ms
	cmd := exec.Command("tc", "qdisc", "add", "dev", tapName, "root", "tbf", "rate", rate, "burst", "32kbit", "latency", "400ms")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to setup QoS: %v", err)
	}
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
