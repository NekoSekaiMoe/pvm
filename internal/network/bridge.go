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
//
// Failures embed the command's combined output: "exit status 2" from
// iptables without the stderr line ("option -d cannot be used multiple
// times", "No chain/target by that name", …) is undiagnosable from logs —
// this repo learned that the hard way when a stacked-"! -d" rule broke
// CI with no actionable message.
var execRun = func(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return nil
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
					// Through execRun (not a direct exec.Command) so test stubs
					// intercept the rollback write too; best-effort as before.
					_ = execRun("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", ipForwardOriginal))
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
	//
	// 出向规则携带 L4 兜底 SSRF floor：每个保留网段一条 DROP、其后一条
	// ACCEPT（单规则堆叠 "! -d" 是非法语法——xtables 基本匹配 -d 每规则
	// 仅允许一次，CI tests/47 实证 exit 2）。即使 tc INGRESS 上的 eBPF
	// 过滤器降级未挂载（StartTask 会审计 degraded warning 继续运行），
	// 私网/云元数据/保留网段也无法被 FORWARD 直达。这层与 egress.c 的
	// BPF floor 覆盖同一网段集合；放行路径不受影响（网关与 guest 自身
	// 流量不走 FORWARD——它们终止在宿主机本地协议栈）。
	for _, rule := range forwardFloorRules("-A", subnetCIDR) {
		if err := execRun("iptables", rule...); err != nil {
			return fmt.Errorf("failed to setup iptables FORWARD out (src %s, rule %q): %v", subnetCIDR, rule, err)
		}
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
			// Through execRun so test stubs intercept the restore write like
			// every other external command.
			if err := execRun("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", ipForwardOriginal)); err != nil {
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
// forwardReserved nets are the destination ranges the L4 SSRF floor denies
// even when forwarding. Kept in sync with bpf/egress.c's compiled-in floor
// (same ranges on both layers).
var forwardReservedNets = []string{
	"0.0.0.0/8",     // "this" network
	"10.0.0.0/8",    // RFC1918
	"100.64.0.0/10", // CGNAT (cloud metadata endpoints)
	"127.0.0.0/8",   // loopback
	"169.254.0.0/16", // link-local (AWS/GCP/Aliyun metadata)
	"172.16.0.0/12", // RFC1918
	"192.168.0.0/16", // RFC1918
	"198.18.0.0/15", // benchmarking
	"224.0.0.0/4",   // multicast
	"240.0.0.0/4",   // reserved (incl. 255.255.255.255)
}

// forwardFloorRules builds the outbound FORWARD rule argv list for op
// ("-A" or "-D"): one DROP per reserved destination range, followed by the
// ACCEPT. SetupBridge and teardownBridge iterate the same list so both stay
// byte-identical — iptables -D only matches a rule with the exact same
// option sequence.
//
// One rule per range (NOT a single rule with stacked "! -d A ! -d B …"):
// xtables allows the basic -d match to appear at most ONCE per rule — a
// second -d is a hard syntax error (iptables exits 2; bit this repo in
// CI, tests/47). Sequential "deny each, then accept the rest" expresses
// the same floor with stock syntax, and an explicit DROP also beats
// falling through to later FORWARD rules that might be looser.
func forwardFloorRules(op, subnetCIDR string) [][]string {
	rules := make([][]string, 0, len(forwardReservedNets)+1)
	for _, reserved := range forwardReservedNets {
		rules = append(rules, []string{op, "FORWARD", "-s", subnetCIDR, "-d", reserved, "-j", "DROP"})
	}
	rules = append(rules, []string{op, "FORWARD", "-s", subnetCIDR, "-j", "ACCEPT"})
	return rules
}

func teardownBridge(bridgeName string, subnetCIDR string) error {
	if subnetCIDR != "" {
		// 与 SetupBridge 对称删除：MASQUERADE + FORWARD 入/出规则。
		// 删除失败不阻断清理（规则可能本来就没加上），使用 -D 静默。
		execRun("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnetCIDR, "!", "-o", bridgeName, "-j", "MASQUERADE")
		for _, rule := range forwardFloorRules("-D", subnetCIDR) {
			execRun("iptables", rule...)
		}
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
		// netlink reports interface ADDRESSES (host bits set, e.g.
		// 10.200.1.5/24); mask to the canonical subnet so teardown uses the
		// same CIDR SetupBridge installed its rules with (10.200.1.0/24).
		if s := maskedSubnet(a.IPNet); s != "" {
			return s
		}
	}
	return ""
}

// maskedSubnet returns the canonical network string for ipnet with the host
// bits of its IP cleared (ipnet.IP.Mask(ipnet.Mask)). Returns "" for a
// nil/empty ipnet, so callers can treat it as "nothing addressable".
func maskedSubnet(ipnet *net.IPNet) string {
	if ipnet == nil || ipnet.IP == nil || ipnet.Mask == nil {
		return ""
	}
	return (&net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()
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
