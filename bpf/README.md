# eBPF Kernel Network Filters (`bpf/`)

This directory contains kernel-level eBPF C source code used for packet filtering and SSRF defense on guest egress TAP interfaces.

---

## Filter Overview (`bpf/egress.c`)

The egress filter attaches to the Traffic Control (TC) subsystem's `clsact` qdisc on each container's TAP interface (`vec0` / `tap0`).

### Enforced Rules

1. **SSRF IP-Floor Drop**: Unconditionally blocks all IPv4 egress traffic directed towards:
   - Loopback: `127.0.0.0/8`
   - Cloud Metadata / Link-Local: `169.254.0.0/16`
   - Private RFC 1918 Class A: `10.0.0.0/8`
   - Private RFC 1918 Class B: `172.16.0.0/12`
   - Private RFC 1918 Class C: `192.168.0.0/16`
2. **BPF Whitelist Hash Map (`whitelist_map`)**: Allows dynamic runtime insertion of explicitly authorized destination IPv4 addresses.
3. **Default Egress Action**: Unmatched non-whitelisted outbound packets are dropped (`TC_ACT_SHOT`).

---

## Compilation & Code Generation

eBPF source files are compiled into Go bindings using `cilium/ebpf/cmd/bpf2go`:

```bash
# Regenerate Go bindings in internal/network
cd internal/network
go generate ./...
```
