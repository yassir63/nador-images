#ifndef NADOR_TCP_REPEAT_H
#define NADOR_TCP_REPEAT_H

#include <stdint.h>

#define TCP_REPEAT_SLOTS 65536u
#define TCP_REPEAT_WINDOW_NS UINT64_C(5000000000)

/* All words are initialized by the caller. No payload is retained. */
struct tcp_repeat_key {
    uint32_t teid, outer_dst_ip, src_ip, dst_ip, ports, seq, payload_len, mode;
};

struct tcp_repeat_entry {
    struct tcp_repeat_key key;
    uint64_t seen_ns;
};

static inline unsigned int tcp_repeat_slot(const struct tcp_repeat_key *k)
{
    uint32_t h = UINT32_C(2166136261);
    const uint32_t words[] = {k->teid, k->outer_dst_ip, k->src_ip, k->dst_ip,
                              k->ports, k->seq, k->payload_len, k->mode};
    for (unsigned int i = 0; i < sizeof(words) / sizeof(words[0]); i++)
        h = (h ^ words[i]) * UINT32_C(16777619);
    return (h ^ (h >> 16)) & (TCP_REPEAT_SLOTS - 1);
}

static inline int tcp_repeat_observe(struct tcp_repeat_entry *table,
                                     const struct tcp_repeat_key *k, uint64_t now_ns)
{
    struct tcp_repeat_entry *slot = &table[tcp_repeat_slot(k)];
    const struct tcp_repeat_key *prev = &slot->key;
    int same = slot->seen_ns && prev->teid == k->teid && prev->outer_dst_ip == k->outer_dst_ip &&
        prev->src_ip == k->src_ip && prev->dst_ip == k->dst_ip && prev->ports == k->ports &&
        prev->seq == k->seq && prev->payload_len == k->payload_len && prev->mode == k->mode;

    /* Ignore timestamps delivered out of order across perf-buffer CPUs. */
    if (now_ns <= slot->seen_ns)
        return 0;
    int repeated = same && now_ns - slot->seen_ns <= TCP_REPEAT_WINDOW_NS;
    slot->key = *k;
    slot->seen_ns = now_ns;
    return repeated;
}
#endif
