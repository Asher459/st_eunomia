#ifndef _NRC_H
#define _NRC_H

#include <linux/types.h>

struct nrc_event {
    __u64 timestamp;
    __u64 retransmit_count;
};

#endif /* _NRC_H */
