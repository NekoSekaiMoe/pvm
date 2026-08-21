package network

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
)

var (
	ipForwardOriginal string
	ipForwardRefCount int
	ipForwardMu       sync.Mutex
)

// execRun runs an external command. It is a package-level variable so tests
// can substitute a recording stub and assert on the exact teardown commands
// DeleteBridge issues (no root/iproute2 required).
var execRun = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// readIPForward reads the current net.ipv4.ip_forward value. Package-level
// like execRun so tests can stub it deterministically.
var readIPForward = func() (string, error) {
	out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// SetupBridge creates a NAT bridge.
// 只有在函数返回错误时才回滚已创建的资源；成功路径必须保留 bridge 与
// ip_forward 状态。早期的 defer 无条件执行 DeleteBridge，会导致成功创建后
// bridge 被立即删掉（表现为 `ip link set <tap> master <br>` 报 device 不存在）。
func SetupBridge(bridgeName string, tapName string, gatewayIP string) (err error) {
	// Track exactly which resources this invocation created/registered so the
	// deferred cleanup only unwinds what we actually own. A failure before, say,
	// ip_forward refcount++ must not touch the refcount or tear down another
	// container's forwarding state.
	bridgeCreated := false
	ipForwardRegistered := false
	natSubnet := "" // set once gatewayIP parses; used for precise rollback
	defer func() {
		// 仅在失败时回滚；成功返回时保留所有已创建的资源。
		if err == nil {
			return
		}
		// Roll back ONLY the resources this invocation owns: the bridge and
		// its NAT rules (teardownBridge never touches the ip_forward
		// refcount — calling DeleteBridge here would decrement a count we
		// may not even have incremented yet).
		if bridgeCreated {
			_ = teardownBridge(bridgeName, natSubnet)
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

	if err := execRun("ip", "link", "add", "name", bridgeName, "type", "bridge"); err != nil {
		return fmt.Errorf("failed to add bridge %s: %v", bridgeName, err)
	}
	bridgeCreated = true
	if err := execRun("ip", "link", "set", bridgeName, "up"); err != nil {
		return fmt.Errorf("failed to set bridge %s up: %v", bridgeName, err)
	}

	if err := execRun("ip", "addr", "add", gatewayIP, "dev", bridgeName); err != nil {
		return fmt.Errorf("failed to add ip to bridge %s: %v", bridgeName, err)
	}

	if tapName != "" {
		if err := execRun("ip", "link", "set", tapName, "master", bridgeName); err != nil {
			return fmt.Errorf("failed to set tap %s master %s: %v", tapName, bridgeName, err)
		}
	}

	// Parse gatewayIP as CIDR to derive the NAT source subnet
	_, ipnet, err := net.ParseCIDR(gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to parse gatewayIP %s: %v", gatewayIP, err)
	}
	subnetCIDR := ipnet.String()
	natSubnet = subnetCIDR

	// Setup NAT (iptables) for the subnet.
	// 注意：MASQUERADE 只改源地址（POSTROUTING/nat），但容器包进入 host 后
	// 首先要经过 filter 表的 FORWARD 链。在 FORWARD policy=DROP 的主机上
	// （如 GHA runner、大多数云主机），没有显式放行规则时包会被丢弃，
	// 表现为 “gateway 能 ping 通但外网/DNS 全部 100% loss”。因此必须同时
	// 配置 FORWARD 链的 ACCEPT 规则。
	if err := execRun("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnetCIDR, "!", "-o", bridgeName, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("failed to setup iptables MASQUERADE: %v", err)
	}
	// 放行从容器子网出外网的转发包，以及已建立连接的返回包。
	if err := execRun("iptables", "-A", "FORWARD", "-s", subnetCIDR, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to setup iptables FORWARD out (src %s): %v", subnetCIDR, err)
	}
	if err := execRun("iptables", "-A", "FORWARD", "-d", subnetCIDR, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to setup iptables FORWARD return: %v", err)
	}

	ipForwardMu.Lock()
	if ipForwardRefCount == 0 {
		val, err := readIPForward()
		if err != nil {
			ipForwardMu.Unlock()
			return fmt.Errorf("failed to read net.ipv4.ip_forward: %v", err)
		}
		if val != "0" && val != "1" {
			ipForwardMu.Unlock()
			return fmt.Errorf("unexpected net.ipv4.ip_forward value %q (expected 0 or 1)", val)
		}
		ipForwardOriginal = val
	}
	ipForwardRefCount++
	ipForwardMu.Unlock()
	ipForwardRegistered = true

	if err := execRun("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("failed to enable ip_forward: %v", err)
	}

	return nil
}

// SetupQoS sets bandwidth limits on a tap interface to prevent abuse.
// rate is whitelisted (^\d+[kmgKMG]bit$) before it reaches tc so a crafted
// value cannot inject additional tc arguments.
var qosRateRe = regexp.MustCompile(`^\d+[kmgKMG]bit$`)

func SetupQoS(tapName string, rate string) error {
	if !qosRateRe.MatchString(rate) {
		return fmt.Errorf("invalid QoS rate %q (want e.g. 10mbit)", rate)
	}
	// e.g. rate="10mbit"
	// tc qdisc add dev tap0 root tbf rate 10mbit burst 32kbit latency 400ms
	cmd := exec.Command("tc", "qdisc", "add", "dev", tapName, "root", "tbf", "rate", rate, "burst", "32kbit", "latency", "400ms")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to setup QoS: %v", err)
	}
	return nil
}

// DeleteBridge removes a bridge and its NAT rules, then decrements the
// ip_forward refcount. When gatewayIP is empty (e.g. `umlctl network rm`
// only knows the name), the subnet is recovered from the addresses still
// configured on the bridge — while the bridge exists those are exactly the
// addresses SetupBridge added, so the MASQUERADE/FORWARD cleanup stays
// symmetric instead of leaking rules forever.
func DeleteBridge(bridgeName string, gatewayIP string) error {
	subnetCIDR := ""
	if gatewayIP != "" {
		if _, ipnet, err := net.ParseCIDR(gatewayIP); err == nil {
			subnetCIDR = ipnet.String()
		}
	} else {
		subnetCIDR = bridgeSubnet(bridgeName)
	}
	if err := teardownBridge(bridgeName, subnetCIDR); err != nil {
		return err
	}

	ipForwardMu.Lock()
	ipForwardRefCount--
	if ipForwardRefCount <= 0 {
		ipForwardRefCount = 0
		if ipForwardOriginal != "" {
			if err := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", ipForwardOriginal)).Run(); err != nil {
				ipForwardMu.Unlock()
				return fmt.Errorf("failed to restore net.ipv4.ip_forward=%s: %v", ipForwardOriginal, err)
			}
			ipForwardOriginal = ""
		}
	}
	ipForwardMu.Unlock()

	return nil
}

// teardownBridge performs the physical/rule teardown WITHOUT touching the
// ip_forward refcount: it deletes the MASQUERADE/FORWARD rules for subnetCIDR
// (when non-empty), brings the link down and deletes it. Used both by the
// public DeleteBridge (which then owns the legitimate refcount decrement)
// and by SetupBridge's rollback path (which must only undo what it owns).
func teardownBridge(bridgeName string, subnetCIDR string) error {
	if subnetCIDR != "" {
		// 与 SetupBridge 对称删除：MASQUERADE + FORWARD 入/出规则。
		// 删除失败不阻断清理（规则可能本来就没加上），使用 -D 静默。
		execRun("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnetCIDR, "!", "-o", bridgeName, "-j", "MASQUERADE")
		execRun("iptables", "-D", "FORWARD", "-s", subnetCIDR, "-j", "ACCEPT")
		execRun("iptables", "-D", "FORWARD", "-d", subnetCIDR, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}

	execRun("ip", "link", "set", bridgeName, "down")
	// 仅在网桥确实不存在时忽略错误；权限不足、设备忙、名称错误等其他
	// 错误必须返回给调用方，否则引用计数和 ip_forward 恢复逻辑会基于
	// “已删除”的假象继续执行。（SetupBridge 的回滚路径自行丢弃该错误。）
	if err := execRun("ip", "link", "delete", bridgeName, "type", "bridge"); err != nil && !isDeviceNotExist(err) {
		return fmt.Errorf("failed to delete bridge %s: %v", bridgeName, err)
	}
	return nil
}

// bridgeSubnet recovers the NAT subnet for bridgeName from the inet
// addresses currently on the link (first IPv4 address wins). Returns "" when
// the bridge does not exist or carries no addressable subnet — there is then
// nothing left to clean up.
func bridgeSubnet(bridgeName string) string {
	link, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return ""
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	for _, a := range addrs {
		if a.IPNet != nil {
			return a.IPNet.String()
		}
	}
	return ""
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
