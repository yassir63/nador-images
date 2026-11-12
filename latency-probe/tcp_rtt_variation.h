#ifndef NADOR_TCP_RTT_VARIATION_H
#define NADOR_TCP_RTT_VARIATION_H

#include <stdint.h>

#define TCP_RTT_VARIATION_IDLE_NS UINT64_C(5000000000)

struct tcp_rtt_variation_state {
    uint64_t timestamp_ns, rtt_ns;
    uint32_t teid, outer_dst_ip;
};

static inline int tcp_rtt_variation_observe(struct tcp_rtt_variation_state *state,
                                            uint32_t teid, uint32_t outer_dst_ip,
                                            uint64_t now_ns, uint64_t rtt_ns,
                                            uint64_t *variation_ns)
{
    if (!rtt_ns || now_ns <= state->timestamp_ns)
        return 0;
    int comparable = state->timestamp_ns &&
        state->teid == teid && state->outer_dst_ip == outer_dst_ip &&
        now_ns - state->timestamp_ns <= TCP_RTT_VARIATION_IDLE_NS;
    if (comparable)
        *variation_ns = rtt_ns >= state->rtt_ns ? rtt_ns - state->rtt_ns : state->rtt_ns - rtt_ns;
    *state = (struct tcp_rtt_variation_state){now_ns, rtt_ns, teid, outer_dst_ip};
    return comparable;
}
#endif
