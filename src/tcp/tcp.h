#ifndef _TCP_H
#define _TCP_H

#include <linux/types.h>


struct tcp_conn_event {
    __u64 timestamp_ns;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u32 conn_type;
};

#endif /* _TCP_H */
