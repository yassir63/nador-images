#ifndef NADOR_TCP_REPEAT_H
#define NADOR_TCP_REPEAT_H

#include <stdint.h>

#define TCP_REPEAT_SLOTS 65536u
#define TCP_REPEAT_WAYS 4u
#define TCP_REPEAT_BUCKETS (TCP_REPEAT_SLOTS / TCP_REPEAT_WAYS)
#define TCP_REPEAT_WINDOW_NS UINT64_C(5000000000)

/* All words are initialized by the caller. No payload is retained. */
struct tcp_repeat_key {
    uint32_t teid, outer_dst_ip, src_ip, dst_ip, ports, seq, payload_len, mode;
};

struct tcp_repeat_entry {
    struct tcp_repeat_key key;
    uint64_t seen_ns;
};

static inline unsigned int tcp_repeat_bucket_start(const struct tcp_repeat_key *k)
{
    uint32_t h = UINT32_C(2166136261);
    const uint32_t words[] = {k->teid, k->outer_dst_ip, k->src_ip, k->dst_ip,
                              k->ports, k->seq, k->payload_len, k->mode};
    for (unsigned int i = 0; i < sizeof(words) / sizeof(words[0]); i++)
        h = (h ^ words[i]) * UINT32_C(16777619);
    return ((h ^ (h >> 16)) & (TCP_REPEAT_BUCKETS - 1)) * TCP_REPEAT_WAYS;
}

static inline int tcp_repeat_key_equal(const struct tcp_repeat_key *a, const struct tcp_repeat_key *b)
{
    return a->teid == b->teid && a->outer_dst_ip == b->outer_dst_ip &&
        a->src_ip == b->src_ip && a->dst_ip == b->dst_ip && a->ports == b->ports &&
        a->seq == b->seq && a->payload_len == b->payload_len && a->mode == b->mode;
}

/* Report the victim's mode only when replacing a still-recent entry. */
static inline int tcp_repeat_observe(struct tcp_repeat_entry *table,
                                     const struct tcp_repeat_key *k, uint64_t now_ns,
                                     uint32_t *evicted_mode)
{
    struct tcp_repeat_entry *bucket = &table[tcp_repeat_bucket_start(k)];
    struct tcp_repeat_entry *oldest = bucket;
    if (evicted_mode)
        *evicted_mode = 0;

    for (unsigned int i = 0; i < TCP_REPEAT_WAYS; i++) {
        struct tcp_repeat_entry *slot = &bucket[i];
        if (slot->seen_ns && tcp_repeat_key_equal(&slot->key, k)) {
            /* Ignore timestamps delivered out of order across perf-buffer CPUs. */
            if (now_ns <= slot->seen_ns)
                return 0;
            int repeated = now_ns - slot->seen_ns <= TCP_REPEAT_WINDOW_NS;
            slot->seen_ns = now_ns;
            return repeated;
        }
        if (slot->seen_ns < oldest->seen_ns)
            oldest = slot;
    }
    if (now_ns <= oldest->seen_ns)
        return 0;
    if (evicted_mode && oldest->seen_ns && now_ns - oldest->seen_ns <= TCP_REPEAT_WINDOW_NS)
        *evicted_mode = oldest->key.mode;
    oldest->key = *k;
    oldest->seen_ns = now_ns;
    return 0;
}
#endif
