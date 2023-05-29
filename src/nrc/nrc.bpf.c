#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include "nrc.h"

struct bpf_map_def SEC("maps") retransmit_map = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

SEC("socket")
int retransmit_count(struct __sk_buff *skb)
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

    // Calculate the retransmission count
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&retransmit_map, &key);
    if (!count) {
        __u64 initial_count = 0;
        bpf_map_update_elem(&retransmit_map, &key, &initial_count, BPF_ANY);
        count = bpf_map_lookup_elem(&retransmit_map, &key);
    }

    if (tcp->ack_seq < *count)
        (*count)++;

    // Emit the retransmission count event
    struct nrc_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.retransmit_count = *count;
    bpf_perf_event_output(skb, &retransmit_map, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}
