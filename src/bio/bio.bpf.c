#include <linux/bpf.h>
#include <bio.h>

struct bpf_map_def SEC("maps") bio_latency_map = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct request *),
    .value_size = sizeof(u64),
    .max_entries = 100,
};

struct data_disk_latency_t {
    u64 latency;
    u32 dev;
    u8 op;
};

SEC("tracepoint/block/block_bio_queue")
int trace_block_bio_queue(struct pt_regs *ctx)
{
    struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
    struct request_queue *q = bio->bi_disk->queue;

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&bio_latency_map, &q, &ts, 0);

    return 0;
}

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct pt_regs *ctx)
{
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);
    struct request_queue *q = req->q;
    struct gendisk *disk = q->queue_hw_ctx;

    u64 *tsp = bpf_map_lookup_elem(&bio_latency_map, &q);
    if (tsp) {
        u64 ts = bpf_ktime_get_ns();
        u64 latency = ts - *tsp;

        struct data_disk_latency_t data = {
            .latency = latency / 1000U,
            .dev = disk ? MKDEV(disk->major, disk->first_minor) : 0,
            .op = req->cmd_flags & REQ_OP_MASK,
        };

        bpf_perf_event_output(ctx, &bio_latency_histogram, BPF_F_CURRENT_CPU, &data, sizeof(data));
        bpf_map_delete_elem(&bio_latency_map, &q);
    }

    return 0;
}
