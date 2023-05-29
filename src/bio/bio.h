#ifndef __BIO_H__
#define __BIO_H__

#include <linux/types.h>

struct bio_key {
    __u64 pid;
    sector_t sector;
};

struct bio_stats {
    __u64 start;
};

#endif /* __BIO_H__ */
