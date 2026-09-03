package network

// portmap.go — static host-port → guest-port mapping (inbound DNAT) for
// bridge-mode tasks.
//
// A mapping publishes one host TCP/UDP port and forwards new inbound
// connections to the task's bridge guest IP:
//
//	iptables -t nat -A PREROUTING -p <proto> --dport <host> -j DNAT --to <guest>:<gport>
//	iptables -t nat -A OUTPUT     -p <proto> --dport <host> -j DNAT --to <guest>:<gport>
//	iptables -A FORWARD -d <guest>/32 -p <proto> --dport <gport> -j ACCEPT
//
// The OUTPUT rule keeps localhost clients working (their packets bypass
// PREROUTING); the FORWARD rule accepts NEW inbound flows (the bridge
// setup's FORWARD rules only accept RELATED,ESTABLISHED replies).
//
// Mappings persist in <stateRoot>/portmappings.json and are re-listable
// after a restart; rule APPLICATION is not replayed on boot (a restart of
// the host flushes iptables anyway — mappings are re-registered by the
// task spec on next launch, and Delete re-removes whatever rules exist).
//
// tc-mode tasks use the bridgeless eBPF plane whose world_ingress program
// only reverse-NATs established sessions; static inbound mapping there
// requires BPF-side support, so the manager refuses with ErrPortMapTCMode.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"uml-container/internal/fsjson"
)

// ErrPortMapTCMode is returned when a mapping is requested for a task
// known to run the bridgeless tc dataplane.
var ErrPortMapTCMode = errors.New("network: port mappings require the bridge dataplane (tc mode has no static inbound NAT)")

// PortMapping is one published host port.
type PortMapping struct {
	TaskID    string    `json:"task"`
	HostPort  int       `json:"host_port"`
	GuestPort int       `json:"guest_port"`
	GuestIP   string    `json:"guest_ip"`
	Protocol  string    `json:"protocol"` // "tcp" | "udp"
	CreatedAt time.Time `json:"created_at"`
}

// portMapRegistry is the durable task → mappings index.
type portMapRegistry struct {
	path     string
	mu       chan struct{}
	mappings map[string][]PortMapping // taskID -> mappings
}

var (
	portMapOnce      bool
	portMapRegistry_ *portMapRegistry
	// portMapInitMu serializes the singleton creation: two concurrent
	// AddPortMapping calls used to both observe nil, build separate
	// registries (each with its own mutex) and overwrite each other's
	// portmappings.json — losing records whose iptables rules stayed.
	portMapInitMu sync.Mutex
)

// LoadPortMapRegistry opens (or creates) the mapping registry under
// stateRoot. It is a process-wide singleton because iptables is itself a
// host-wide singleton — concurrent writers must serialize somewhere.
func LoadPortMapRegistry(stateRoot string) (*portMapRegistry, error) {
	portMapInitMu.Lock()
	defer portMapInitMu.Unlock()
	if portMapRegistry_ != nil {
		return portMapRegistry_, nil
	}
	if stateRoot == "" {
		// Mirror state.RootDir: non-root and test runs redirect all
		// durable state via $PVM_STATE_ROOT. Without this the lazy API
		// callers would try to create /var/lib/uml-container on
		// unprivileged runners and every portmap request would fail
		// (DELETE of a nonexistent mapping answered 500, not 404).
		stateRoot = os.Getenv("PVM_STATE_ROOT")
	}
	if stateRoot == "" {
		stateRoot = "/var/lib/uml-container"
	}
	path := filepath.Join(stateRoot, "portmappings.json")
	if err := os.MkdirAll(stateRoot, 0o755); err != nil {
		return nil, fmt.Errorf("portmap registry: %w", err)
	}
	r := &portMapRegistry{path: path, mu: make(chan struct{}, 1), mappings: map[string][]PortMapping{}}
	r.mu <- struct{}{}
	<-r.mu
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		var dump struct {
			Mappings []PortMapping `json:"mappings"`
		}
		if jerr := json.Unmarshal(raw, &dump); jerr == nil {
			for _, m := range dump.Mappings {
				r.mappings[m.TaskID] = append(r.mappings[m.TaskID], m)
			}
		}
	}
	portMapRegistry_ = r
	return r, nil
}

func (r *portMapRegistry) save() error {
	dump := struct {
		Mappings []PortMapping `json:"mappings"`
	}{}
	for _, ms := range r.mappings {
		dump.Mappings = append(dump.Mappings, ms...)
	}
	return fsjson.Write(r.path, dump)
}

// portMapRules returns the exact iptables argv sets for one mapping:
// apply=true installs (-A), apply=false removes (-D with the same spec).
// Pure function — unit-tested without touching the host.
func portMapRules(m PortMapping, apply bool) [][]string {
	action := "-A"
	if !apply {
		action = "-D"
	}
	dnat := fmt.Sprintf("%s:%d", m.GuestIP, m.GuestPort)
	proto := m.Protocol
	if proto == "" {
		proto = "tcp"
	}
	return [][]string{
		{"iptables", "-t", "nat", action, "PREROUTING", "-p", proto, "--dport", strconv.Itoa(m.HostPort), "-j", "DNAT", "--to-destination", dnat},
		{"iptables", "-t", "nat", action, "OUTPUT", "-p", proto, "--dport", strconv.Itoa(m.HostPort), "-j", "DNAT", "--to-destination", dnat},
		{"iptables", action, "FORWARD", "-d", m.GuestIP + "/32", "-p", proto, "--dport", strconv.Itoa(m.GuestPort), "-j", "ACCEPT"},
	}
}

// validatePortMapping checks the invariants before anything touches
// iptables or the registry.
func validatePortMapping(m PortMapping) error {
	if m.TaskID == "" {
		return errors.New("network: port mapping requires a task id")
	}
	if m.HostPort < 1 || m.HostPort > 65535 {
		return fmt.Errorf("network: host port %d out of range", m.HostPort)
	}
	if m.GuestPort < 1 || m.GuestPort > 65535 {
		return fmt.Errorf("network: guest port %d out of range", m.GuestPort)
	}
	switch m.Protocol {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("network: port mapping protocol %q must be tcp or udp", m.Protocol)
	}
	ip := net.ParseIP(m.GuestIP)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("network: port mapping guest ip %q must be IPv4", m.GuestIP)
	}
	return nil
}

// iptablesTimeout bounds every iptables invocation: the calls run while
// r.mu is held, so an iptables lock contention or a wedged child must not
// block AddPortMapping/DeletePortMapping/lists indefinitely.
const iptablesTimeout = 15 * time.Second

// runIptablesCtx executes argv under a deadline (apply path). Failures
// carry the combined iptables output so the caller's error text names the
// real cause.
func runIptablesCtx(ctx context.Context, argv []string) error {
	if err := argvValid(argv); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, iptablesTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(argv[1:], " "), ctx.Err(), strings.TrimSpace(string(out)))
	}
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runIptables executes one argv set with a bounded timeout (apply path).
func runIptables(argv []string) error {
	return runIptablesCtx(context.Background(), argv)
}

// runIptablesDelete removes one rule idempotently WITHOUT parsing
// iptables error text (the historical "Bad rule" sniff broke under
// iptables-nft and localized builds). The -D argv is first probed with
// the equivalent -C check: exit 0 means the rule exists (remove it for
// real), exit 1 is the documented "rule does not exist" (nothing to
// do), and any other -C outcome (permission denied, no binary) falls
// through to -D so ITS error — the truthful one — reaches the caller.
func runIptablesDelete(del []string) error {
	if err := argvValid(del); err != nil {
		return err
	}
	check := append([]string(nil), del...)
	for i, tok := range check {
		if tok == "-D" {
			check[i] = "-C"
			break
		}
	}
	if cerr := runIptablesCtx(context.Background(), check); cerr == nil {
		// Rule exists: remove it for real.
		return runIptables(del)
	} else if exitCode(cerr) == 1 {
		return nil // documented "rule does not exist": idempotent removal
	}
	// -C failed for a real reason (permission denied, binary missing,
	// table locked): run -D and let ITS error — the truthful one — speak.
	return runIptables(del)
}

// exitCode extracts the process exit status; -1 when the command never
// ran (binary not found, killed by signal before exec).
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func argvValid(argv []string) error {
	if len(argv) == 0 || argv[0] != "iptables" {
		return errors.New("network: internal error: non-iptables argv")
	}
	return nil
}

// AddPortMapping validates, applies and records one mapping. Duplicate
// (task, protocol, hostPort) is a conflict.
func AddPortMapping(m PortMapping) error {
	if m.Protocol == "" {
		m.Protocol = "tcp"
	}
	if err := validatePortMapping(m); err != nil {
		return err
	}
	r, err := LoadPortMapRegistry("")
	if err != nil {
		return err
	}
	r.mu <- struct{}{}
	defer func() { <-r.mu }()
	// The host port namespace is HOST-WIDE (one iptables PREROUTING):
	// a duplicate (protocol, hostPort) from ANY task would be shadowed by
	// the first-installed DNAT rule and silently forward to the wrong
	// task. Reject across all tasks, not just this one.
	for _, ms := range r.mappings {
		for _, ex := range ms {
			if ex.Protocol == m.Protocol && ex.HostPort == m.HostPort {
				return fmt.Errorf("network: host port %d/%s already mapped (task %q)", m.HostPort, m.Protocol, ex.TaskID)
			}
		}
	}
	for _, argv := range portMapRules(m, true) {
		if err := runIptables(argv); err != nil {
			// Roll back the rules already applied.
			for _, back := range portMapRules(m, false) {
				_ = runIptablesDelete(back)
			}
			return fmt.Errorf("network: apply port mapping: %w", err)
		}
	}
	m.CreatedAt = time.Now().UTC()
	r.mappings[m.TaskID] = append(r.mappings[m.TaskID], m)
	return r.save()
}

// DeletePortMapping removes one mapping (rules + record). Missing mapping
// is an error the API maps to 404.
func DeletePortMapping(taskID string, hostPort int, proto string) error {
	if proto == "" {
		proto = "tcp"
	}
	r, err := LoadPortMapRegistry("")
	if err != nil {
		return err
	}
	r.mu <- struct{}{}
	defer func() { <-r.mu }()
	ms := r.mappings[taskID]
	for i, ex := range ms {
		if ex.Protocol == proto && ex.HostPort == hostPort {
			for _, argv := range portMapRules(ex, false) {
				if err := runIptablesDelete(argv); err != nil {
					return fmt.Errorf("network: remove port mapping: %w", err)
				}
			}
			r.mappings[taskID] = append(ms[:i], ms[i+1:]...)
			if len(r.mappings[taskID]) == 0 {
				delete(r.mappings, taskID)
			}
			return r.save()
		}
	}
	return os.ErrNotExist
}

// CleanupTaskPortMappings removes every mapping of a task (teardown path).
func CleanupTaskPortMappings(taskID string) error {
	r, err := LoadPortMapRegistry("")
	if err != nil {
		return err
	}
	r.mu <- struct{}{}
	defer func() { <-r.mu }()
	ms := r.mappings[taskID]
	if len(ms) == 0 {
		return nil
	}
	for _, m := range ms {
		for _, argv := range portMapRules(m, false) {
			_ = runIptablesDelete(argv) // best-effort
		}
	}
	delete(r.mappings, taskID)
	return r.save()
}

// ListPortMappings returns all recorded mappings (sorted for stable API
// output).
func ListPortMappings() []PortMapping {
	r, err := LoadPortMapRegistry("")
	if err != nil {
		return nil
	}
	r.mu <- struct{}{}
	defer func() { <-r.mu }()
	out := make([]PortMapping, 0, 8)
	for _, ms := range r.mappings {
		out = append(out, ms...)
	}
	return out
}

// PortMappingsFor returns one task's mappings.
func PortMappingsFor(taskID string) []PortMapping {
	r, err := LoadPortMapRegistry("")
	if err != nil {
		return nil
	}
	r.mu <- struct{}{}
	defer func() { <-r.mu }()
	return append([]PortMapping(nil), r.mappings[taskID]...)
}
