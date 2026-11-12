#include <assert.h>
#include "tcp_repeat.h"
#include "tcp_rtt_variation.h"

static struct tcp_repeat_entry table[TCP_REPEAT_SLOTS];

static void test_rtt_variation(void)
{
    struct tcp_rtt_variation_state state = {0};
    uint64_t delta = 0;
    assert(!tcp_rtt_variation_observe(&state, 42, 1, 100, 10000000, &delta));
    assert(tcp_rtt_variation_observe(&state, 42, 1, 200, 14000000, &delta) && delta == 4000000);
    assert(!tcp_rtt_variation_observe(&state, 42, 1, 199, 90000000, &delta));
    assert(tcp_rtt_variation_observe(&state, 42, 1, 300, 11000000, &delta) && delta == 3000000);
    assert(tcp_rtt_variation_observe(&state, 42, 1, 400, 11000000, &delta) && delta == 0);
    assert(!tcp_rtt_variation_observe(&state, 42, 2, 500, 90000000, &delta));
    assert(!tcp_rtt_variation_observe(&state, 42, 2, TCP_RTT_VARIATION_IDLE_NS + 501, 1000000, &delta));
}

int main(void)
{
    test_rtt_variation();
    struct tcp_repeat_key data = {
        .teid = 42, .outer_dst_ip = 1, .src_ip = 2, .dst_ip = 3,
        .ports = 4, .seq = 5, .payload_len = 100, .mode = 1,
    };
    assert(!tcp_repeat_observe(table, &data, 100));
    assert(!tcp_repeat_observe(table, &data, 99));
    assert(!tcp_repeat_observe(table, &data, 100));
    assert(tcp_repeat_observe(table, &data, 101));
    assert(!tcp_repeat_observe(table, &data, TCP_REPEAT_WINDOW_NS + 102));

    struct tcp_repeat_key other = data;
    other.teid++;
    assert(!tcp_repeat_observe(table, &other, TCP_REPEAT_WINDOW_NS + 103));
    other = data;
    other.outer_dst_ip++;
    assert(!tcp_repeat_observe(table, &other, TCP_REPEAT_WINDOW_NS + 104));
    other = data;
    other.mode++;
    assert(!tcp_repeat_observe(table, &other, TCP_REPEAT_WINDOW_NS + 105));
    other = data;
    other.payload_len++;
    assert(!tcp_repeat_observe(table, &other, TCP_REPEAT_WINDOW_NS + 106));
    return 0;
}
