#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include "tcprtt.h"

struct bpf_map_def SEC("maps") tcprtt_map = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct tcprtt_key),
    .value_size = sizeof(struct tcprtt_stats),
    .max_entries = 100,
};

SEC("socket")
int tcprtt(struct __sk_buff *skb)
{
    // Retrieve the TCP header
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

    // Filter TCP packets only
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Calculate TCP round-trip time (RTT)
    struct tcprtt_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest
    };
    struct tcprtt_stats *stats = bpf_map_lookup_elem(&tcprtt_map, &key);
    if (!stats) {
        // Initialize the stats if not found in the map
        struct tcprtt_stats new_stats = {
            .rtt_sum = 0,
            .rtt_count = 0,
            .last_ack_seq = 0,
            .last_ack_timestamp = 0
        };
        bpf_map_update_elem(&tcprtt_map, &key, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&tcprtt_map, &key);
    }

    if (stats) {
        if (tcp->ack_seq > stats->last_ack_seq) {
            __u64 rtt = bpf_ktime_get_ns() - stats->last_ack_timestamp;
            stats->rtt_sum += rtt;
            stats->rtt_count++;
            stats->last_ack_seq = tcp->ack_seq;
            stats->last_ack_timestamp = bpf_ktime_get_ns();
        }
    }

    return XDP_PASS;
}
