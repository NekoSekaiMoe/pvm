#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} whitelist_map SEC(".maps");

SEC("tc")
int egress_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;
        
    // Allow UDP (e.g. DNS) to pass through so we can resolve domains
    if (ip->protocol == 17) {
        return TC_ACT_OK;
    }

    // SSRF Protection: Block internal IP addresses regardless of whitelist
    __u32 dest_ip_host = __builtin_bswap32(ip->daddr);
    // 10.0.0.0/8
    if ((dest_ip_host & 0xFF000000) == 0x0A000000) return TC_ACT_SHOT;
    // 172.16.0.0/12
    if ((dest_ip_host & 0xFFF00000) == 0xAC100000) return TC_ACT_SHOT;
    // 192.168.0.0/16
    if ((dest_ip_host & 0xFFFF0000) == 0xC0A80000) return TC_ACT_SHOT;

    __u32 dest_ip = ip->daddr;
    __u32 *allowed = bpf_map_lookup_elem(&whitelist_map, &dest_ip);
    
    if (allowed && *allowed == 1) {
        return TC_ACT_OK;
    }

    // Default DROP for non-whitelisted TCP traffic
    return TC_ACT_SHOT;
}

char __license[] SEC("license") = "Dual MIT/GPL";
