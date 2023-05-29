//#include "tcp.h"
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/ptrace.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/libbpf.h>
#include "stubs-32.h"

#include <linux/ptrace.h>
#include <linux/ip.h>
#include <bpf/libbpf.h>

struct tcp_conn_event {
    __u64 timestamp_ns;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u32 conn_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tcp_conn_events SEC(".maps");

SEC("kprobe/tcp_v4_connect")

int trace_tcp_connect(struct pt_regs *ctx) {
    struct tcp_conn_event event = {};
    struct sock *skp = NULL;
    struct tcphdr *tcph = NULL;
    struct iphdr *iph = NULL;

    // Get the socket from the function argument
    skp = (struct sock *)PT_REGS_PARM1(ctx);

    // Extract IP and TCP headers
    iph = (struct iphdr *)((__u32 *)skp + 1);
    tcph = (struct tcphdr *)(iph + 1);

    // Fill in the event data
    event.timestamp_ns = bpf_ktime_get_ns();
    event.saddr = iph->saddr;
    event.daddr = iph->daddr;
    event.sport = tcph->source;
    event.dport = tcph->dest;
    event.conn_type = 0; // 0 for connection setup

    // Send the event to userspace
    bpf_perf_event_output(ctx, &tcp_conn_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";

