#ifndef TCPRTT_H
#define TCPRTT_H

#include <linux/types.h>

struct tcprtt_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

struct tcprtt_stats {
    __u64 rtt_sum;
    __u64 rtt_count;
    __u32 last_ack_seq;
    __u64 last_ack_timestamp;
};

#endif /* TCPRTT_H */
