// bpf/tap_dataplane.c
//
// P2: CubeVS-style bridgeless TC/eBPF data plane (opt-in via the TaskSpec's
// network.dataplane = "tc"). Three TC programs replace the Linux bridge +
// iptables model; every sandbox shares the same fixed link-local addressing
// (guest 169.254.68.6, gateway/proxy 169.254.68.5) and traffic is steered /
// NATed entirely in TC:
//
//   tap_ingress   TAP ingress (guest -> host):
//                 - dst == gateway (169.254.68.5): learn the
//                   listener-port -> TAP mapping the reply loop needs, then
//                   redirect into the host stack through the pvm-gw dummy
//                   device (BPF_F_INGRESS) so the L7 proxy / DNS learner
//                   bound on 169.254.68.5 receive it.
//                 - otherwise: SSRF floor + per-task shared whitelist_map
//                   (same schema as bpf/egress.c), then SNAT — src IP ->
//                   host egress IP, src port -> the task's port window — a
//                   session entry is created and the packet is emitted via
//                   bpf_redirect_neigh() on the host NIC. redirect_neigh
//                   performs the route lookup + neighbor resolution in the
//                   kernel, so no ip_forward sysctl, no FIB lookup and no
//                   host MAC constants are needed.
//   world_ingress host NIC ingress (world -> guest):
//                 - reply 5-tuple hits egress_sessions => reverse-DNAT back
//                   to the fixed guest address/port, L2 rewrite to the
//                   learned MACs, bpf_redirect() into the task's TAP (TX =
//                   guest RX). Non-matching packets pass (TC_ACT_OK) so
//                   host traffic is unaffected; several tasks chain their
//                   own world_ingress filters on one NIC (distinct handles).
//   gw_egress     pvm-gw egress (proxy/DNS replies -> guest):
//                 - the host routes 169.254.68.0/24 via pvm-gw; the reply's
//                   L4 source port is the task's listener port, which
//                   gw_port_map maps to the owning TAP. L2 rewrite +
//                   bpf_redirect() into that TAP.
//
// IPv4 + TCP/UDP only. ICMP (and any non-TCP/UDP protocol) from the guest
// is SHOT: no ICMP NAT state is tracked, and the guest's link-local address
// must never leak onto the wire. Packets with IP options (ihl != 5) are
// dropped on the NAT path so header offsets stay static and the verifier
// sees straight-line bounds checks.
//
// All per-task values (host egress IP, ifindexes, port window base, fixed
// IPs) are load-time constants rewritten via RewriteConstants by
// internal/network/dataplane.go (same pattern as egress.c's exempt_ip_a/b);
// 0 means "unset" and never matches a packet.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
/* -1: skip this filter, continue down the chain. Required on shared devices
 * (host NIC, pvm-gw) where several per-task filters chain on one hook:
 * TC_ACT_OK would TERMINATE the chain and steal packets from the tasks
 * whose filters sit at later priorities. */
#define TC_ACT_UNSPEC -1

#ifndef BPF_F_INGRESS
#define BPF_F_INGRESS (1ULL << 0)
#endif

/* Avoid pulling <linux/in.h>: only the two protocol numbers are needed. */
#define L4PROTO_TCP 6
#define L4PROTO_UDP 17

/* Header offsets (ihl == 5 is enforced on the NAT path). */
#define IP_OFF (ETH_HLEN)
#define IP_CHECK_OFF (ETH_HLEN + 10) /* offsetof(struct iphdr, check) */
#define IP_SADDR_OFF (ETH_HLEN + 12) /* offsetof(struct iphdr, saddr) */
#define IP_DADDR_OFF (ETH_HLEN + 16) /* offsetof(struct iphdr, daddr) */
#define L4_OFF (ETH_HLEN + 20)
#define L4_SPORT_OFF (L4_OFF)
#define L4_DPORT_OFF (L4_OFF + 2)
#define TCP_CHECK_OFF (L4_OFF + 16) /* offsetof(struct tcphdr, check) */
#define UDP_CHECK_OFF (L4_OFF + 6)  /* offsetof(struct udphdr, check) */

/* dp_stats indexes (names mirrored in internal/network/dataplane.go). */
#define ST_DROP_POLICY 0 /* SSRF floor or whitelist denied */
#define ST_DROP_PROTO 1  /* ICMP / non-TCP-UDP / IPv6 / IP options */
#define ST_DROP_NAT 2    /* no free source port in the task window */
#define ST_SESSIONS_NEW 3
#define ST_NAT_FWD 4 /* SNATed and redirected to the world */
#define ST_GW_FWD 5  /* redirected to the host stack via pvm-gw */
#define ST_REV_FWD 6 /* reverse-DNATed and redirected to the TAP */
#define ST_GW_LOOP 7 /* proxy/DNS replies looped back into the TAP */
#define ST_MAX 8

/* NAT port window geometry (mirrored in internal/network/dataplane.go). */
#define NAT_WINDOW 1024
#define NAT_ATTEMPTS 8

/* Shared egress policy: SAME schema as bpf/egress.c's whitelist_map so the
 * loader can swap in the already-pinned per-task map via MapReplacements
 * (one policy map consulted by both programs; `agentpvm network whitelist
 * add` and dnslearn keep working unchanged in tc mode). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
    // No LIBBPF_PIN_BY_NAME: pinning is userspace-controlled per task
    // (/sys/fs/bpf/pvm/<taskID>/whitelist_map).
} whitelist_map SEC(".maps");

/* NAT session table, keyed by the REPLY 5-tuple (what the world sends
 * back): remote ip/port + the NATed (host) ip/port + protocol. The value
 * carries everything the reverse path needs so no second lookup is
 * required: original guest tuple, the task's TAP ifindex and the two
 * learned MACs. */
struct session_key {
    __u32 remote_ip;   /* network order */
    __u32 nat_ip;      /* network order (host egress IP) */
    __u16 remote_port; /* network order */
    __u16 nat_port;    /* network order */
    __u8 proto;
    __u8 pad[3];
};

struct session_value {
    __u32 guest_ip;   /* network order (169.254.68.6) */
    __u16 guest_port; /* network order (original guest src port) */
    __u16 pad;
    __u32 tap_ifindex;
    __u8 guest_mac[ETH_ALEN]; /* eth src of the guest's packet */
    __u8 gw_mac[ETH_ALEN];    /* eth dst the guest chose (its "gateway") */
    __u64 last_seen_ns;       /* bpf_ktime_get_ns; idle-swept from Go */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct session_key);
    __type(value, struct session_value);
    // Pinned per task at /sys/fs/bpf/pvm/<taskID>/egress_sessions.
} egress_sessions SEC(".maps");

/* Proxy reply loop: listener port (network order) -> owning TAP + MACs.
 * tap_ingress learns an entry on every gateway-bound packet (the guest
 * dials 169.254.68.5:<listener port>); gw_egress consults it for replies
 * whose SOURCE port is that listener port. Per task: listener ports are
 * unique host-wide because every task binds its own ephemeral port on the
 * same 169.254.68.5 address. */
struct gw_target {
    __u32 tap_ifindex;
    __u8 guest_mac[ETH_ALEN];
    __u8 gw_mac[ETH_ALEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct gw_target);
    // Pinned per task at /sys/fs/bpf/pvm/<taskID>/gw_port_map.
} gw_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ST_MAX);
    __type(key, __u32);
    __type(value, __u64);
    // Pinned per task at /sys/fs/bpf/pvm/<taskID>/dp_stats.
} dp_stats SEC(".maps");

/* Load-time per-task constants (RewriteConstants before load). All IPs are
 * the raw __u32 form a packet field carries (network-order bytes), matching
 * how ip->saddr/daddr read; ifindexes are host-order. */
const volatile __u32 host_ip = 0;         /* host egress (SNAT) address */
const volatile __u32 guest_ip = 0;        /* fixed 169.254.68.6 */
const volatile __u32 proxy_ip = 0;        /* fixed 169.254.68.5 */
const volatile __u32 host_nic_ifindex = 0;
const volatile __u32 gw_dev_ifindex = 0;  /* pvm-gw dummy device */
const volatile __u32 tap_dev_ifindex = 0; /* this task's TAP */
const volatile __u32 port_base = 0;       /* first SNAT port (host order) */

static __always_inline void stats_inc(__u32 idx)
{
    __u64 *ctr = bpf_map_lookup_elem(&dp_stats, &idx);
    if (ctr)
        *ctr += 1;
}

/* tap_ingress: guest -> host policy + SNAT + session create + redirect.
 * Attached to the task TAP's clsact ingress (dedicated device, fixed
 * handle). Only IPv4 TCP/UDP ever leaves this program alive; ARP passes so
 * the host (weak-host model) can answer the guest's gateway ARP. */
SEC("tc")
int tap_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto == __builtin_bswap16(ETH_P_ARP))
        return TC_ACT_OK;
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_SHOT; /* IPv6 and friends: no tc-mode support */

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_SHOT;
    if (ip->ihl != 5) {
        /* IP options would shift the L4 offsets; drop instead of NATing
         * with static offsets (a passthrough would leak the link-local
         * source to the host stack, which drops it as a martian anyway). */
        stats_inc(ST_DROP_PROTO);
        return TC_ACT_SHOT;
    }

    /* TCP and UDP share the source/destination port layout, so the first
     * 4 bytes of either header are read through this common shape. */
    struct l4ports {
        __u16 sport;
        __u16 dport;
    } *l4 = (void *)(ip + 1);
    /* sizeof(struct tcphdr) also covers sizeof(struct udphdr). */
    if ((void *)l4 + sizeof(struct tcphdr) > data_end)
        return TC_ACT_SHOT;

    __u8 proto = ip->protocol;
    if (proto != L4PROTO_TCP && proto != L4PROTO_UDP) {
        /* ICMP included: no NAT state is tracked for it (documented). */
        stats_inc(ST_DROP_PROTO);
        return TC_ACT_SHOT;
    }

    /* Snapshot every header field needed past this point: the mutation
     * helpers below invalidate packet pointers. */
    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u16 sport = l4->sport;
    __u16 dport = l4->dport;
    __u16 l4_check = 0;
    if (proto == L4PROTO_UDP) {
        struct udphdr *udp = (void *)l4;
        l4_check = udp->check; /* 0 => no L4 csum fixups needed (IPv4) */
    }
    __u8 guest_mac[ETH_ALEN];
    __u8 gw_mac[ETH_ALEN];
    __builtin_memcpy(guest_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(gw_mac, eth->h_dest, ETH_ALEN);

    /* Gateway/proxy path: hand the frame to the host stack on pvm-gw. The
     * listener-port mapping is (re)learned first so the SYN's own reply
     * already finds gw_port_map populated. */
    if (proxy_ip && daddr == proxy_ip) {
        struct gw_target tgt;
        __builtin_memset(&tgt, 0, sizeof(tgt));
        tgt.tap_ifindex = tap_dev_ifindex;
        __builtin_memcpy(tgt.guest_mac, guest_mac, ETH_ALEN);
        __builtin_memcpy(tgt.gw_mac, gw_mac, ETH_ALEN);
        bpf_map_update_elem(&gw_port_map, &dport, &tgt, BPF_ANY);
        stats_inc(ST_GW_FWD);
        return bpf_redirect(gw_dev_ifindex, BPF_F_INGRESS);
    }

    /* The guest's own address as a destination makes no sense here (the
     * fixed address is shared by every sandbox); let the host stack deal
     * with it (it drops it: no local route off pvm-gw). */
    if (guest_ip && daddr == guest_ip)
        return TC_ACT_OK;

    /* SSRF floor (same ranges as bpf/egress.c; the fixed gateway/guest
     * addresses are handled above and never reach the 169.254/16 drop). */
    __u32 dst_host = __builtin_bswap32(daddr);
    if ((dst_host & 0xFF000000) == 0x7F000000) /* 127.0.0.0/8 loopback */
        goto drop_policy;
    if ((dst_host & 0xFFFF0000) == 0xA9FE0000) /* 169.254.0.0/16 link-local */
        goto drop_policy;
    if ((dst_host & 0xFF000000) == 0x0A000000) /* 10.0.0.0/8 */
        goto drop_policy;
    if ((dst_host & 0xFFF00000) == 0xAC100000) /* 172.16.0.0/12 */
        goto drop_policy;
    if ((dst_host & 0xFFFF0000) == 0xC0A80000) /* 192.168.0.0/16 */
        goto drop_policy;

    __u32 *allowed = bpf_map_lookup_elem(&whitelist_map, &daddr);
    if (!allowed || *allowed != 1)
        goto drop_policy;

    /* SNAT session setup: pick a source port inside the task's window,
     * retrying on collision with another guest flow (up to NAT_ATTEMPTS).
     * A collision with the SAME guest tuple is a retransmission / flow
     * refresh and reuses the existing entry. */
    if (host_ip == 0 || port_base == 0 || host_nic_ifindex == 0)
        goto drop_nat; /* loader contract violated: fail closed */

    __u32 sport_host = __builtin_bswap16(sport);
    __u16 nat_port = 0;
    struct session_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.remote_ip = daddr;
    key.nat_ip = host_ip;
    key.remote_port = dport;
    key.proto = proto;

#pragma unroll
    for (int i = 0; i < NAT_ATTEMPTS; i++) {
        __u32 cand = port_base + ((sport_host + i) & (NAT_WINDOW - 1));
        key.nat_port = __builtin_bswap16(cand);

        struct session_value val;
        __builtin_memset(&val, 0, sizeof(val));
        val.guest_ip = saddr;
        val.guest_port = sport;
        val.tap_ifindex = tap_dev_ifindex;
        __builtin_memcpy(val.guest_mac, guest_mac, ETH_ALEN);
        __builtin_memcpy(val.gw_mac, gw_mac, ETH_ALEN);
        val.last_seen_ns = bpf_ktime_get_ns();

        if (bpf_map_update_elem(&egress_sessions, &key, &val,
                                BPF_NOEXIST) == 0) {
            nat_port = key.nat_port;
            stats_inc(ST_SESSIONS_NEW);
            break;
        }
        struct session_value *old =
            bpf_map_lookup_elem(&egress_sessions, &key);
        if (old && old->guest_ip == saddr && old->guest_port == sport) {
            old->last_seen_ns = bpf_ktime_get_ns();
            nat_port = key.nat_port;
            break;
        }
    }
    if (nat_port == 0)
        goto drop_nat;

    /* Checksum fixups first, then the field writes; a failure of the very
     * first fixup means the skb is not writable and the rest would corrupt
     * the packet, so bail instead of emitting garbage. */
    if (bpf_l3_csum_replace(skb, IP_CHECK_OFF, saddr, host_ip, 4))
        return TC_ACT_SHOT;
    __u32 l4_check_off = proto == L4PROTO_TCP ? TCP_CHECK_OFF : UDP_CHECK_OFF;
    if (proto == L4PROTO_TCP || l4_check != 0) {
        bpf_l4_csum_replace(skb, l4_check_off, saddr, host_ip,
                            BPF_F_PSEUDO_HDR | 4);
        bpf_l4_csum_replace(skb, l4_check_off, sport, nat_port, 2);
    }
    __u32 host_ip_v = host_ip;
    bpf_skb_store_bytes(skb, IP_SADDR_OFF, &host_ip_v, 4, 0);
    bpf_skb_store_bytes(skb, L4_SPORT_OFF, &nat_port, 2, 0);

    stats_inc(ST_NAT_FWD);
    /* redirect_neigh does the route lookup (post-NAT src/dst) and neighbor
     * resolution in the kernel and emits the frame with the correct L2 —
     * no FIB helper (no ip_forward requirement) and no host MAC constants.
     * The L2 header is left as-is on purpose: redirect_neigh pulls it. */
    return bpf_redirect_neigh(host_nic_ifindex, NULL, 0, 0);

drop_policy:
    stats_inc(ST_DROP_POLICY);
    return TC_ACT_SHOT;
drop_nat:
    stats_inc(ST_DROP_NAT);
    return TC_ACT_SHOT;
}

/* world_ingress: world -> guest reverse NAT. Attached to the HOST NIC's
 * clsact ingress with a per-task handle (several tasks chain on one NIC;
 * non-matching traffic must pass untouched). */
SEC("tc")
int world_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (ip->ihl != 5)
        return TC_ACT_UNSPEC; /* not ours to mangle; the host stack decides */

    struct l4ports {
        __u16 sport;
        __u16 dport;
    } *l4 = (void *)(ip + 1);
    if ((void *)l4 + sizeof(struct tcphdr) > data_end)
        return TC_ACT_UNSPEC;

    __u8 proto = ip->protocol;
    if (proto != L4PROTO_TCP && proto != L4PROTO_UDP)
        return TC_ACT_UNSPEC;

    struct session_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.remote_ip = ip->saddr;
    key.nat_ip = ip->daddr;
    key.remote_port = l4->sport;
    key.nat_port = l4->dport;
    key.proto = proto;

    struct session_value *val = bpf_map_lookup_elem(&egress_sessions, &key);
    if (!val)
        return TC_ACT_UNSPEC; /* host traffic: untouched */

    /* Copy everything needed before the mutating helpers run. */
    __u32 guest_ip_v = val->guest_ip;
    __u16 guest_port = val->guest_port;
    __u32 tap_ifindex = val->tap_ifindex;
    __u8 guest_mac[ETH_ALEN];
    __u8 gw_mac[ETH_ALEN];
    __builtin_memcpy(guest_mac, val->guest_mac, ETH_ALEN);
    __builtin_memcpy(gw_mac, val->gw_mac, ETH_ALEN);

    __u32 old_daddr = ip->daddr;
    __u16 old_dport = l4->dport;
    __u16 l4_check = 0;
    if (proto == L4PROTO_UDP) {
        struct udphdr *udp = (void *)l4;
        l4_check = udp->check;
    }

    /* Reverse DNAT: dst -> original guest tuple. */
    if (bpf_l3_csum_replace(skb, IP_CHECK_OFF, old_daddr, guest_ip_v, 4))
        return TC_ACT_SHOT;
    __u32 l4_check_off = proto == L4PROTO_TCP ? TCP_CHECK_OFF : UDP_CHECK_OFF;
    if (proto == L4PROTO_TCP || l4_check != 0) {
        bpf_l4_csum_replace(skb, l4_check_off, old_daddr, guest_ip_v,
                            BPF_F_PSEUDO_HDR | 4);
        bpf_l4_csum_replace(skb, l4_check_off, old_dport, guest_port, 2);
    }
    bpf_skb_store_bytes(skb, IP_DADDR_OFF, &guest_ip_v, 4, 0);
    bpf_skb_store_bytes(skb, L4_DPORT_OFF, &guest_port, 2, 0);
    /* L2: the guest's MAC as destination; the MAC the guest believes is
     * its gateway as source (learned from the original packet). */
    bpf_skb_store_bytes(skb, 0, guest_mac, ETH_ALEN, 0);
    bpf_skb_store_bytes(skb, ETH_ALEN, gw_mac, ETH_ALEN, 0);

    /* Refresh the idle timer: full value rewrite (lookup pointers into the
     * map are not written through here so the Go sweeper sees a coherent
     * record). */
    struct session_value upd;
    __builtin_memset(&upd, 0, sizeof(upd));
    upd.guest_ip = guest_ip_v;
    upd.guest_port = guest_port;
    upd.tap_ifindex = tap_ifindex;
    __builtin_memcpy(upd.guest_mac, guest_mac, ETH_ALEN);
    __builtin_memcpy(upd.gw_mac, gw_mac, ETH_ALEN);
    upd.last_seen_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&egress_sessions, &key, &upd, BPF_EXIST);

    stats_inc(ST_REV_FWD);
    return bpf_redirect(tap_ifindex, 0); /* TAP TX = guest RX */
}

/* gw_egress: proxy/DNS reply loop on the pvm-gw dummy device. The host
 * routes 169.254.68.0/24 via pvm-gw; the reply's L4 source port is the
 * per-task listener port, which selects the owning TAP. The dummy driver
 * would blackhole the packet; we redirect it to the guest instead. */
SEC("tc")
int gw_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (ip->ihl != 5)
        return TC_ACT_UNSPEC;

    struct l4ports {
        __u16 sport;
        __u16 dport;
    } *l4 = (void *)(ip + 1);
    if ((void *)l4 + sizeof(struct tcphdr) > data_end)
        return TC_ACT_UNSPEC;

    __u8 proto = ip->protocol;
    if (proto != L4PROTO_TCP && proto != L4PROTO_UDP)
        return TC_ACT_UNSPEC;

    __u16 listen_port = l4->sport;
    struct gw_target *tgt = bpf_map_lookup_elem(&gw_port_map, &listen_port);
    if (!tgt)
        return TC_ACT_UNSPEC; /* not a known task listener: dummy drops it */

    __u32 tap_ifindex = tgt->tap_ifindex;
    __u8 guest_mac[ETH_ALEN];
    __u8 gw_mac[ETH_ALEN];
    __builtin_memcpy(guest_mac, tgt->guest_mac, ETH_ALEN);
    __builtin_memcpy(gw_mac, tgt->gw_mac, ETH_ALEN);

    bpf_skb_store_bytes(skb, 0, guest_mac, ETH_ALEN, 0);
    bpf_skb_store_bytes(skb, ETH_ALEN, gw_mac, ETH_ALEN, 0);

    stats_inc(ST_GW_LOOP);
    return bpf_redirect(tap_ifindex, 0); /* TAP TX = guest RX */
}

char __license[] SEC("license") = "Dual MIT/GPL";
