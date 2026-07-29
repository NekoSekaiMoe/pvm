package network

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

var (
	ipForwardOriginal string
	ipForwardRefCount int
	ipForwardMu       sync.Mutex
)

// SetupBridge creates a NAT bridge
func SetupBridge(bridgeName string, tapName string, gatewayIP string) error {
	success := false
	defer func() {
		if !success {
			DeleteBridge(bridgeName, gatewayIP)
		}
	}()

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

	// Parse gatewayIP as CIDR to derive the NAT source subnet
	_, ipnet, err := net.ParseCIDR(gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to parse gatewayIP %s: %v", gatewayIP, err)
	}
	subnetCIDR := ipnet.String()

	// Setup NAT (iptables) for the subnet
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnetCIDR, "!", "-o", bridgeName, "-j", "MASQUERADE").Run(); err != nil {
		return fmt.Errorf("failed to setup iptables NAT: %v", err)
	}

	ipForwardMu.Lock()
	if ipForwardRefCount == 0 {
		if out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output(); err == nil {
			ipForwardOriginal = strings.TrimSpace(string(out))
		}
	}
	ipForwardRefCount++
	ipForwardMu.Unlock()

	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		ipForwardMu.Lock()
		ipForwardRefCount--
		ipForwardMu.Unlock()
		return fmt.Errorf("failed to enable ip_forward: %v", err)
	}

	success = true
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
func DeleteBridge(bridgeName string, gatewayIP string) error {
	if gatewayIP != "" {
		if _, ipnet, err := net.ParseCIDR(gatewayIP); err == nil {
			subnetCIDR := ipnet.String()
			exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnetCIDR, "!", "-o", bridgeName, "-j", "MASQUERADE").Run()
		}
	}

	exec.Command("ip", "link", "set", bridgeName, "down").Run()
	if err := exec.Command("ip", "link", "delete", "name", bridgeName, "type", "bridge").Run(); err != nil {
		return fmt.Errorf("failed to delete bridge %s: %v", bridgeName, err)
	}

	ipForwardMu.Lock()
	ipForwardRefCount--
	if ipForwardRefCount <= 0 {
		ipForwardRefCount = 0
		if ipForwardOriginal != "" {
			exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", ipForwardOriginal)).Run()
		}
	}
	ipForwardMu.Unlock()

	return nil
}
