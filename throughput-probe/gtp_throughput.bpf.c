/* Keep Linux types before helpers and the shared packet parser. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "gtp_packet.h"

struct tunnel_stats {
    __u64 packets;
    __u64 bytes;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct tunnel_key);
    __type(value, __u8);
} tracked_tunnels SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct tunnel_key);
    __type(value, struct tunnel_stats);
} tunnel_stats SEC(".maps");

/* Per-CPU counters avoid per-packet userspace events; forwarding is unchanged. */
static __always_inline int count_packet(struct __sk_buff *skb) {
    struct tunnel_key key = {};
    __u32 bytes;
    if (parse_gtpu(skb, &key, &bytes) < 0 || !bpf_map_lookup_elem(&tracked_tunnels, &key))
        return TC_ACT_PIPE;
    struct tunnel_stats *stats = bpf_map_lookup_elem(&tunnel_stats, &key);
    if (!stats) {
        struct tunnel_stats initial = {};
        bpf_map_update_elem(&tunnel_stats, &key, &initial, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&tunnel_stats, &key);
    }
    if (stats) {
        stats->packets++;
        stats->bytes += bytes;
    }
    return TC_ACT_PIPE;
}
SEC("tc") int tc_gtp_ingress(struct __sk_buff *skb) {
    return count_packet(skb);
}
SEC("tc") int tc_gtp_egress(struct __sk_buff *skb) {
    return count_packet(skb);
}
char LICENSE[] SEC("license") = "GPL";
