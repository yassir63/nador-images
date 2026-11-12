#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "gtp_latency.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#define GTP_PORT 2152
#define MAX_GTP_EXTENSION_HEADERS 4

struct tcp_tracking_t {
    __u64 timestamp_ns;
    __u32 expected_ack;
} __attribute__((packed));

struct full_flow_id_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 seq;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));    // TEID
    __uint(value_size, sizeof(__u32));  // Slice ID
    __uint(max_entries, 1024);
} teid_slice_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct icmp_id_t));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} core_icmp_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct icmp_id_t));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} ran_icmp_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct full_flow_id_t));
    __uint(value_size, sizeof(struct tcp_tracking_t));
    __uint(max_entries, 2048);
} core_flow_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct full_flow_id_t));
    __uint(value_size, sizeof(struct tcp_tracking_t));
    __uint(max_entries, 2048);
} ran_flow_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32)); // UL TEID
    __uint(value_size, sizeof(__u32)); // DL TEID
    __uint(max_entries, 64);
} teid_pair_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // TEID
    __uint(value_size, sizeof(__u8)); // any value, e.g., 1
    __uint(max_entries, 1024);
} tracked_teids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} teid_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} latency_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} flow_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} tcp_observation_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} icmp_debug_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct latency_config_t));
    __uint(max_entries, 1);
} latency_config_map SEC(".maps");

static __always_inline __u8 get_latency_mode(void)
{
    __u32 key = 0;
    struct latency_config_t *cfg = bpf_map_lookup_elem(&latency_config_map, &key);

    if (!cfg || cfg->mode == 0)
        return LATENCY_MODE_CORE;

    return cfg->mode;
}

static __always_inline int match_debug_enabled(void)
{
    __u32 key = 0;
    struct latency_config_t *cfg = bpf_map_lookup_elem(&latency_config_map, &key);

    return cfg && cfg->debug;
}

static __always_inline __u8 get_probe_role(void)
{
    __u32 key = 0;
    struct latency_config_t *cfg = bpf_map_lookup_elem(&latency_config_map, &key);

    if (!cfg || cfg->role == 0)
        return PROBE_ROLE_GNB;

    return cfg->role;
}

static __always_inline int mode_enabled(__u8 configured_mode, __u8 candidate_mode)
{
    return configured_mode == LATENCY_MODE_BOTH || configured_mode == candidate_mode;
}

static __always_inline int is_logical_uplink(__u8 probe_role, __u8 direction)
{
    if (probe_role == PROBE_ROLE_UPF)
        return direction == 0; // UPF N3 ingress is gNB/UE -> UPF.

    return direction == 1; // gNB N3 egress is UE -> core.
}

static __always_inline int is_logical_downlink(__u8 probe_role, __u8 direction)
{
    if (probe_role == PROBE_ROLE_UPF)
        return direction == 1; // UPF N3 egress is UPF -> gNB/UE.

    return direction == 0; // gNB N3 ingress is core -> UE.
}

static __always_inline void emit_latency_event(
    struct __sk_buff *skb,
    __u32 teid,
    __u64 latency_ns,
    __u64 sent_ns,
    __u64 acked_ns,
    __u8 mode,
    __u8 kind)
{
    struct latency_event_t latency_evt = {};
    struct iphdr outer_ip = {};
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &outer_ip, sizeof(outer_ip)) < 0)
        return;
    latency_evt.outer_dst_ip = outer_ip.daddr;

    latency_evt.teid = teid;
    latency_evt.latency_ns = latency_ns;
    latency_evt.sent_ns = sent_ns;
    latency_evt.acked_ns = acked_ns;
    latency_evt.mode = mode;
    latency_evt.kind = kind;

    bpf_perf_event_output(skb, &latency_events, BPF_F_CURRENT_CPU, &latency_evt, sizeof(latency_evt));
}

static __always_inline void emit_tcp_observation_event(
    struct __sk_buff *skb,
    __u32 teid,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 src_port,
    __u16 dst_port,
    __u32 seq,
    __u32 ack_seq,
    __u32 seq_advance,
    __u32 payload_len,
    __u8 direction,
    __u8 mode,
    __u8 flags,
    __u8 observation)
{
    struct tcp_observation_event_t evt = {};
    struct iphdr outer_ip = {};
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &outer_ip, sizeof(outer_ip)) < 0)
        return;
    evt.outer_dst_ip = outer_ip.daddr;

    evt.teid = teid;
    evt.src_ip = src_ip;
    evt.dst_ip = dst_ip;
    evt.src_port = src_port;
    evt.dst_port = dst_port;
    evt.seq = seq;
    evt.ack_seq = ack_seq;
    evt.seq_advance = seq_advance;
    evt.payload_len = payload_len;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.direction = direction;
    evt.mode = mode;
    evt.flags = flags;
    evt.observation = observation;

    bpf_perf_event_output(skb, &tcp_observation_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

static __always_inline void emit_icmp_debug_event(
    struct __sk_buff *skb,
    __u32 teid,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 id,
    __u16 sequence,
    __u8 direction,
    __u8 mode,
    __u8 type,
    __u8 action)
{
    if (!match_debug_enabled())
        return;

    struct icmp_debug_event_t evt = {};

    evt.teid = teid;
    evt.src_ip = src_ip;
    evt.dst_ip = dst_ip;
    evt.id = id;
    evt.sequence = sequence;
    evt.direction = direction;
    evt.mode = mode;
    evt.type = type;
    evt.action = action;

    bpf_perf_event_output(skb, &icmp_debug_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

static __noinline int is_gtp_packet(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return 0;
    if (bpf_ntohs(eth.h_proto) != ETH_P_IP)
        return 0;

    if (bpf_skb_load_bytes(skb, sizeof(eth), &iph, sizeof(iph)) < 0)
        return 0;
    // Only first fragments contain the UDP/GTP headers identifying the tunnel.
    if (iph.protocol != IPPROTO_UDP || (bpf_ntohs(iph.frag_off) & 0x1fff))
        return 0;

    int ip_header_len = iph.ihl * 4;
    int udp_offset = sizeof(eth) + ip_header_len;
    if (bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0)
        return 0;

    __u16 dport = bpf_ntohs(udp.dest);
    __u16 sport = bpf_ntohs(udp.source);

    return dport == GTP_PORT || sport == GTP_PORT;
}

static __noinline int compute_payload_offset(
    struct __sk_buff *skb,
    int gtp_offset,
    __u8 flags,
    int *payload_offset)
{
    __u8 has_ext = flags & 0x04;
    __u8 has_seq = flags & 0x02;
    __u8 has_pn  = flags & 0x01;

    int offset = gtp_offset + 8;

    if (has_ext || has_seq || has_pn)
        offset += 4;

    if (has_ext) {
        // Your previous logic, kept, but with explicit bounds checks
        int ext_header_start = offset - 1;

#pragma unroll
        for (int i = 0; i < MAX_GTP_EXTENSION_HEADERS; i++) {
            __u8 ext_type = 0;
            if (bpf_skb_load_bytes(skb, ext_header_start, &ext_type, 1) < 0)
                return -1;
            if (ext_type == 0)
                break;

            __u8 ext_len = 0;
            if (bpf_skb_load_bytes(skb, ext_header_start + 1, &ext_len, 1) < 0)
                return -1;

            int ext_content_len = (ext_len == 1) ? 2 : (ext_len * 4);
            int next_ext_type_offset = ext_header_start + 2 + ext_content_len;

            if (next_ext_type_offset >= (int)skb->len)
                return -1;

            __u8 next_ext_type = 0;
            if (bpf_skb_load_bytes(skb, next_ext_type_offset, &next_ext_type, 1) < 0)
                return -1;

            ext_header_start = next_ext_type_offset + 1;

            if (next_ext_type == 0)
                break;
        }

        offset = ext_header_start;
    }

    *payload_offset = offset;
    return 0;
}

static __noinline int parse_teid_and_payload_offset(
    struct __sk_buff *skb,
    __u32 *teid_out,
    int *payload_offset)
{
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return -1;
    if (bpf_ntohs(eth.h_proto) != ETH_P_IP)
        return -1;

    if (bpf_skb_load_bytes(skb, sizeof(eth), &iph, sizeof(iph)) < 0)
        return -1;
    if (iph.protocol != IPPROTO_UDP || (bpf_ntohs(iph.frag_off) & 0x1fff))
        return -1;

    int ip_header_len = iph.ihl * 4;
    int udp_offset = sizeof(eth) + ip_header_len;
    if (bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0)
        return -1;

    if (bpf_ntohs(udp.dest) != GTP_PORT && bpf_ntohs(udp.source) != GTP_PORT)
        return -1;

    int gtp_offset = udp_offset + sizeof(udp);
    unsigned char gtp_hdr[8];
    if (bpf_skb_load_bytes(skb, gtp_offset, gtp_hdr, sizeof(gtp_hdr)) < 0)
        return -1;

    __u8 flags = gtp_hdr[0];
    *teid_out = bpf_ntohl(*((__u32 *)&gtp_hdr[4]));

    return compute_payload_offset(skb, gtp_offset, flags, payload_offset);
}

static __noinline void parse_inner_ipv4_flow(
    struct __sk_buff *skb,
    int offset,
    __u32 teid,
    __u8 direction)
{
    __u8 maybe_ip_header = 0;
    if (bpf_skb_load_bytes(skb, offset, &maybe_ip_header, 1) < 0)
        return;

    __u8 version = maybe_ip_header >> 4;

    // Always zero-init before perf output (verifier safe)
    if (version != 4) {
        struct flow_event_t evt = {};
        evt.teid = teid;
        evt.proto = 255;
        evt.direction = direction;
        evt.timestamp_ns = bpf_ktime_get_ns();
        bpf_perf_event_output(skb, &flow_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return;
    }

    struct iphdr inner_iph;
    if (bpf_skb_load_bytes(skb, offset, &inner_iph, sizeof(inner_iph)) < 0)
        return;

    int ip_len = inner_iph.ihl * 4;
    int ip_packet_len = bpf_ntohs(inner_iph.tot_len);
    // Inner IP fragments lack the complete TCP segment length; do not guess it.
    if (ip_len < 20 || ip_packet_len < ip_len || (bpf_ntohs(inner_iph.frag_off) & 0x3fff))
        return;

    struct flow_event_t evt = {};
    evt.teid = teid;
    evt.src_ip = inner_iph.saddr;
    evt.dst_ip = inner_iph.daddr;
    evt.proto = inner_iph.protocol;
    evt.src_port = 0;
    evt.dst_port = 0;
    evt.direction = direction;
    evt.timestamp_ns = bpf_ktime_get_ns();

    int l4_offset = offset + ip_len;
    __u8 configured_mode = get_latency_mode();
    __u8 probe_role = get_probe_role();
    int logical_uplink = is_logical_uplink(probe_role, direction);
    int logical_downlink = is_logical_downlink(probe_role, direction);

    if (evt.proto == IPPROTO_TCP || evt.proto == IPPROTO_UDP) {
        struct { __u16 src, dst; } ports = {};
        if (bpf_skb_load_bytes(skb, l4_offset, &ports, sizeof(ports)) >= 0) {
            evt.src_port = bpf_ntohs(ports.src);
            evt.dst_port = bpf_ntohs(ports.dst);
        }
    }

    // TCP latency tracking
    if (evt.proto == IPPROTO_TCP) {
        struct {
            __u16 src;
            __u16 dst;
            __u32 seq;
            __u32 ack_seq;
            __u8  offset;
            __u8  flags;
        } tcp_hdr = {};

        if (bpf_skb_load_bytes(skb, l4_offset, &tcp_hdr, sizeof(tcp_hdr)) >= 0) {
            int tcp_hdr_len = (tcp_hdr.offset >> 4) * 4;
            if (tcp_hdr_len < 20 || ip_packet_len < ip_len + tcp_hdr_len ||
                l4_offset + tcp_hdr_len > skb->len)
                return;
            // The inner IP length covers the whole TCP segment, including across outer fragments.
            int tcp_payload_len = ip_packet_len - ip_len - tcp_hdr_len;
            __u32 seq = bpf_ntohl(tcp_hdr.seq);
            __u32 ack_seq = bpf_ntohl(tcp_hdr.ack_seq);
            __u8 ack_flag = tcp_hdr.flags & 0x10;
            __u32 payload_len_u32 = 0;
            __u32 seq_advance = 0;

            payload_len_u32 = (__u32)tcp_payload_len;
            seq_advance = payload_len_u32;
            if (tcp_hdr.flags & 0x02) // SYN consumes one TCP sequence number.
                seq_advance += 1;
            if (tcp_hdr.flags & 0x01) // FIN consumes one TCP sequence number.
                seq_advance += 1;

            __u8 data_mode = logical_uplink ? LATENCY_MODE_CORE : LATENCY_MODE_RAN;
            if ((tcp_hdr.flags & 0x04) && mode_enabled(configured_mode, data_mode))
                emit_tcp_observation_event(
                    skb, teid, inner_iph.saddr, inner_iph.daddr,
                    evt.src_port, evt.dst_port, seq, ack_seq, seq_advance,
                    payload_len_u32, direction, data_mode, tcp_hdr.flags, TCP_OBS_RESET);

            if (mode_enabled(configured_mode, LATENCY_MODE_CORE)) {
                if (logical_uplink && ack_flag && seq_advance > 0) {
                    struct full_flow_id_t fid = {};
                    struct tcp_tracking_t track = {};

                    fid.src_ip = inner_iph.saddr;
                    fid.dst_ip = inner_iph.daddr;
                    fid.src_port = evt.src_port;
                    fid.dst_port = evt.dst_port;
                    fid.seq = seq + seq_advance;

                    track.timestamp_ns = bpf_ktime_get_ns();
                    track.expected_ack = fid.seq;

                    bpf_map_update_elem(&core_flow_ts_map, &fid, &track, BPF_ANY);
                }

                if (logical_downlink && ack_flag) {
                    struct full_flow_id_t reverse_fid = {};
                    struct tcp_tracking_t *track;

                    reverse_fid.src_ip = inner_iph.daddr;
                    reverse_fid.dst_ip = inner_iph.saddr;
                    reverse_fid.src_port = evt.dst_port;
                    reverse_fid.dst_port = evt.src_port;
                    reverse_fid.seq = ack_seq;

                    track = bpf_map_lookup_elem(&core_flow_ts_map, &reverse_fid);
                    if (track) {
                        __u64 now = bpf_ktime_get_ns();

                        emit_latency_event(
                            skb,
                            teid,
                            now - track->timestamp_ns,
                            track->timestamp_ns,
                            now,
                            LATENCY_MODE_CORE,
                            LATENCY_KIND_TCP_ACK);
                        bpf_map_delete_elem(&core_flow_ts_map, &reverse_fid);
                    }
                }
            }

            if (mode_enabled(configured_mode, LATENCY_MODE_RAN)) {
                if (logical_downlink && ack_flag && seq_advance > 0) {
                    struct full_flow_id_t fid = {};
                    struct tcp_tracking_t track = {};

                    fid.src_ip = inner_iph.saddr;
                    fid.dst_ip = inner_iph.daddr;
                    fid.src_port = evt.src_port;
                    fid.dst_port = evt.dst_port;
                    fid.seq = seq + seq_advance;

                    track.timestamp_ns = bpf_ktime_get_ns();
                    track.expected_ack = fid.seq;

                    bpf_map_update_elem(&ran_flow_ts_map, &fid, &track, BPF_ANY);
                }

                if (logical_uplink && ack_flag) {
                    struct full_flow_id_t reverse_fid = {};
                    struct tcp_tracking_t *track;

                    reverse_fid.src_ip = inner_iph.daddr;
                    reverse_fid.dst_ip = inner_iph.saddr;
                    reverse_fid.src_port = evt.dst_port;
                    reverse_fid.dst_port = evt.src_port;
                    reverse_fid.seq = ack_seq;

                    track = bpf_map_lookup_elem(&ran_flow_ts_map, &reverse_fid);
                    if (track) {
                        __u64 now = bpf_ktime_get_ns();

                        emit_latency_event(
                            skb,
                            teid,
                            now - track->timestamp_ns,
                            track->timestamp_ns,
                            now,
                            LATENCY_MODE_RAN,
                            LATENCY_KIND_TCP_ACK);
                        bpf_map_delete_elem(&ran_flow_ts_map, &reverse_fid);
                    }
                }
            }

            if (mode_enabled(configured_mode, LATENCY_MODE_CORE)) {
                if (logical_uplink && ack_flag && seq_advance > 0) {
                    emit_tcp_observation_event(
                        skb, teid, inner_iph.saddr, inner_iph.daddr,
                        evt.src_port, evt.dst_port, seq, ack_seq, seq_advance,
                        payload_len_u32, direction, LATENCY_MODE_CORE,
                        tcp_hdr.flags, TCP_OBS_CORE_DATA);
                }

                if (logical_downlink && ack_flag) {
                    emit_tcp_observation_event(
                        skb, teid, inner_iph.saddr, inner_iph.daddr,
                        evt.src_port, evt.dst_port, seq, ack_seq, seq_advance,
                        payload_len_u32, direction, LATENCY_MODE_CORE,
                        tcp_hdr.flags, TCP_OBS_CORE_ACK);
                }
            }

            if (mode_enabled(configured_mode, LATENCY_MODE_RAN)) {
                if (logical_downlink && ack_flag && seq_advance > 0) {
                    emit_tcp_observation_event(
                        skb, teid, inner_iph.saddr, inner_iph.daddr,
                        evt.src_port, evt.dst_port, seq, ack_seq, seq_advance,
                        payload_len_u32, direction, LATENCY_MODE_RAN,
                        tcp_hdr.flags, TCP_OBS_RAN_DATA);
                }

                if (logical_uplink && ack_flag) {
                    emit_tcp_observation_event(
                        skb, teid, inner_iph.saddr, inner_iph.daddr,
                        evt.src_port, evt.dst_port, seq, ack_seq, seq_advance,
                        payload_len_u32, direction, LATENCY_MODE_RAN,
                        tcp_hdr.flags, TCP_OBS_RAN_ACK);
                }
            }
        }
    }

    // ICMP latency tracking (zero-init any emitted struct)
    if (evt.proto == IPPROTO_ICMP) {
        struct icmp_echo_hdr_t {
            __u8  type;
            __u8  code;
            __be16 checksum;
            __be16 id;
            __be16 sequence;
        } icmp = {};

        if (bpf_skb_load_bytes(skb, l4_offset, &icmp, sizeof(icmp)) >= 0) {
            __u16 icmp_id = bpf_ntohs(icmp.id);
            __u16 icmp_sequence = bpf_ntohs(icmp.sequence);

            if (mode_enabled(configured_mode, LATENCY_MODE_CORE)) {
                if (logical_uplink && icmp.type == 8) {
                    struct icmp_id_t key = {};
                    __u64 now = bpf_ktime_get_ns();

                    key.src_ip = inner_iph.saddr;
                    key.dst_ip = inner_iph.daddr;
                    key.id = icmp_id;

                    bpf_map_update_elem(&core_icmp_ts_map, &key, &now, BPF_ANY);
                    emit_icmp_debug_event(
                        skb, teid, inner_iph.saddr, inner_iph.daddr,
                        icmp_id, icmp_sequence, direction, LATENCY_MODE_CORE,
                        icmp.type, ICMP_DEBUG_CORE_STORE);
                }

                if (logical_downlink && icmp.type == 0) {
                    struct icmp_id_t reverse_key = {};
                    __u64 *start;

                    reverse_key.src_ip = inner_iph.daddr;
                    reverse_key.dst_ip = inner_iph.saddr;
                    reverse_key.id = icmp_id;

                    start = bpf_map_lookup_elem(&core_icmp_ts_map, &reverse_key);
                    if (start) {
                        __u64 now = bpf_ktime_get_ns();

                        emit_latency_event(
                            skb,
                            teid,
                            now - *start,
                            *start,
                            now,
                            LATENCY_MODE_CORE,
                            LATENCY_KIND_ICMP_ECHO);
                        emit_icmp_debug_event(
                            skb, teid, inner_iph.saddr, inner_iph.daddr,
                            icmp_id, icmp_sequence, direction, LATENCY_MODE_CORE,
                            icmp.type, ICMP_DEBUG_CORE_MATCH);
                        bpf_map_delete_elem(&core_icmp_ts_map, &reverse_key);
                    } else {
                        emit_icmp_debug_event(
                            skb, teid, inner_iph.saddr, inner_iph.daddr,
                            icmp_id, icmp_sequence, direction, LATENCY_MODE_CORE,
                            icmp.type, ICMP_DEBUG_CORE_MISS);
                    }
                }
            }

            if (mode_enabled(configured_mode, LATENCY_MODE_RAN)) {
                if (logical_downlink && icmp.type == 8) {
                    struct icmp_id_t key = {};
                    __u64 now = bpf_ktime_get_ns();

                    key.src_ip = inner_iph.saddr;
                    key.dst_ip = inner_iph.daddr;
                    key.id = icmp_id;

                    bpf_map_update_elem(&ran_icmp_ts_map, &key, &now, BPF_ANY);
                    emit_icmp_debug_event(
                        skb, teid, inner_iph.saddr, inner_iph.daddr,
                        icmp_id, icmp_sequence, direction, LATENCY_MODE_RAN,
                        icmp.type, ICMP_DEBUG_RAN_STORE);
                }

                if (logical_uplink && icmp.type == 0) {
                    struct icmp_id_t reverse_key = {};
                    __u64 *start;

                    reverse_key.src_ip = inner_iph.daddr;
                    reverse_key.dst_ip = inner_iph.saddr;
                    reverse_key.id = icmp_id;

                    start = bpf_map_lookup_elem(&ran_icmp_ts_map, &reverse_key);
                    if (start) {
                        __u64 now = bpf_ktime_get_ns();

                        emit_latency_event(
                            skb,
                            teid,
                            now - *start,
                            *start,
                            now,
                            LATENCY_MODE_RAN,
                            LATENCY_KIND_ICMP_ECHO);
                        emit_icmp_debug_event(
                            skb, teid, inner_iph.saddr, inner_iph.daddr,
                            icmp_id, icmp_sequence, direction, LATENCY_MODE_RAN,
                            icmp.type, ICMP_DEBUG_RAN_MATCH);
                        bpf_map_delete_elem(&ran_icmp_ts_map, &reverse_key);
                    } else {
                        emit_icmp_debug_event(
                            skb, teid, inner_iph.saddr, inner_iph.daddr,
                            icmp_id, icmp_sequence, direction, LATENCY_MODE_RAN,
                            icmp.type, ICMP_DEBUG_RAN_MISS);
                    }
                }
            }
        }
    }

    bpf_perf_event_output(skb, &flow_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

SEC("tc")
int tc_gtp_teid_ingress(struct __sk_buff *skb) {
    if (!is_gtp_packet(skb))
        return TC_ACT_PIPE;

    __u32 teid = 0;
    int payload_offset = 0;

    if (parse_teid_and_payload_offset(skb, &teid, &payload_offset) < 0) {
        if (teid == 0) teid = 0xdeadbeef;

        struct flow_event_t failed_evt = {};
        failed_evt.teid = teid;
        failed_evt.proto = 255;
        failed_evt.direction = 0;
        failed_evt.timestamp_ns = bpf_ktime_get_ns();

        bpf_perf_event_output(skb, &flow_events, BPF_F_CURRENT_CPU, &failed_evt, sizeof(failed_evt));
        return TC_ACT_PIPE;
    }

    // ZERO-INIT FIX HERE
    struct teid_event_t evt = {};
    evt.teid = teid;
    evt.source = 0;
    bpf_perf_event_output(skb, &teid_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    parse_inner_ipv4_flow(skb, payload_offset, teid, 0);
    return TC_ACT_PIPE;
}

SEC("tc")
int tc_gtp_teid_egress(struct __sk_buff *skb) {
    if (!is_gtp_packet(skb))
        return TC_ACT_PIPE;

    __u32 teid = 0;
    int payload_offset = 0;

    if (parse_teid_and_payload_offset(skb, &teid, &payload_offset) < 0) {
        if (teid == 0) teid = 0xdeadbeef;

        struct flow_event_t failed_evt = {};
        failed_evt.teid = teid;
        failed_evt.proto = 255;
        failed_evt.direction = 1;
        failed_evt.timestamp_ns = bpf_ktime_get_ns();

        bpf_perf_event_output(skb, &flow_events, BPF_F_CURRENT_CPU, &failed_evt, sizeof(failed_evt));
        return TC_ACT_PIPE;
    }

    // ZERO-INIT FIX HERE
    struct teid_event_t evt = {};
    evt.teid = teid;
    evt.source = 1;
    bpf_perf_event_output(skb, &teid_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    parse_inner_ipv4_flow(skb, payload_offset, teid, 1);
    return TC_ACT_PIPE;
}

char LICENSE[] SEC("license") = "GPL";
