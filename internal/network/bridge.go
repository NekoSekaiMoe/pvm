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
	// Track exactly which resources this invocation created/registered so the
	// deferred cleanup only unwinds what we actually own. A failure before, say,
	// ip_forward refcount++ must not touch the refcount or tear down another
	// container's forwarding state.
	bridgeCreated := false
	ipForwardRegistered := false
	defer func() {
		if bridgeCreated {
			DeleteBridge(bridgeName, gatewayIP)
		}
		// If we incremented the refcount but failed to actually enable ip_forward,
		// roll back our registration so the count stays honest.
		if ipForwardRegistered {
			ipForwardMu.Lock()
			ipForwardRefCount--
			if ipForwardRefCount <= 0 {
				ipForwardRefCount = 0
				if ipForwardOriginal != "" {
					exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", ipForwardOriginal)).Run()
				}
			}
			ipForwardMu.Unlock()
		}
	}()

	if err := exec.Command("ip", "link", "add", "name", bridgeName, "type", "bridge").Run(); err != nil {
		return fmt.Errorf("failed to add bridge %s: %v", bridgeName, err)
	}
	bridgeCreated = true
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
		out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
		if err != nil {
			ipForwardMu.Unlock()
			return fmt.Errorf("failed to read net.ipv4.ip_forward: %v", err)
		}
		val := strings.TrimSpace(string(out))
		if val != "0" && val != "1" {
			ipForwardMu.Unlock()
			return fmt.Errorf("unexpected net.ipv4.ip_forward value %q (expected 0 or 1)", val)
		}
		ipForwardOriginal = val
	}
	ipForwardRefCount++
	ipForwardMu.Unlock()
	ipForwardRegistered = true

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
func DeleteBridge(bridgeName string, gatewayIP string) error {
	if gatewayIP != "" {
		if _, ipnet, err := net.ParseCIDR(gatewayIP); err == nil {
			subnetCIDR := ipnet.String()
			exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnetCIDR, "!", "-o", bridgeName, "-j", "MASQUERADE").Run()
		}
	}

	exec.Command("ip", "link", "set", bridgeName, "down").Run()
	// 仅在网桥确实不存在时忽略错误；权限不足、设备忙、名称错误等其他
	// 错误必须返回给调用方，否则引用计数和 ip_forward 恢复逻辑会基于
	// “已删除”的假象继续执行。
	if err := exec.Command("ip", "link", "delete", bridgeName, "type", "bridge").Run(); err != nil {
		if !isDeviceNotExist(err) {
			return fmt.Errorf("failed to delete bridge %s: %v", bridgeName, err)
		}
	}

	ipForwardMu.Lock()
	ipForwardRefCount--
	if ipForwardRefCount <= 0 {
		ipForwardRefCount = 0
		if ipForwardOriginal != "" {
			if err := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", ipForwardOriginal)).Run(); err != nil {
				return fmt.Errorf("failed to restore net.ipv4.ip_forward=%s: %v", ipForwardOriginal, err)
			}
			ipForwardOriginal = ""
		}
	}
	ipForwardMu.Unlock()

	return nil
}

// isDeviceNotExist reports whether err from `ip link delete` indicates the
// device simply does not exist (the only case where we silently continue).
func isDeviceNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "cannot find device") || strings.Contains(msg, "device not found") || strings.Contains(msg, "no such device")
}
