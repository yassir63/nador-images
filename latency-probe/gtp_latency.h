#ifndef __GTP_LATENCY_H__
#define __GTP_LATENCY_H__

#include <linux/types.h>

enum debug_step_t {
    DEBUG_STEP_GTP_FLAGS            = 1,
    DEBUG_STEP_GTP_OFFSET           = 2,
    DEBUG_STEP_EXT_START            = 10,
    DEBUG_STEP_EXT_TYPE             = 20,
    DEBUG_STEP_EXT_LEN              = 30,
    DEBUG_STEP_EXT_NEXT_TYPE        = 40,
    DEBUG_STEP_EXT_END              = 250,
    DEBUG_STEP_PAYLOAD_OFFSET       = 201,
    DEBUG_STEP_PAYLOAD_BYTE         = 200,
    DEBUG_STEP_IP_VERSION           = 102,
    DEBUG_STEP_EXT_LOAD_TYPE_FAIL   = 251,
    DEBUG_STEP_EXT_LOAD_LEN_FAIL    = 252,
    DEBUG_STEP_EXT_LOAD_NEXT_FAIL   = 253,
    DEBUG_STEP_EXT_BOUNDS_EXCEEDED  = 254,
    DEBUG_STEP_PAYLOAD_PARSE_FAIL   = 255,
};

enum latency_mode_t {
    LATENCY_MODE_CORE = 1,
    LATENCY_MODE_RAN  = 2,
    LATENCY_MODE_BOTH = 3,
};

enum latency_kind_t {
    LATENCY_KIND_TCP_ACK   = 1,
    LATENCY_KIND_ICMP_ECHO = 2,
};

enum probe_role_t {
    PROBE_ROLE_GNB = 1,
    PROBE_ROLE_UPF = 2,
};

struct latency_config_t {
    __u8 mode;
    __u8 debug;
    __u8 role;
    __u8 reserved;
};

enum icmp_debug_action_t {
    ICMP_DEBUG_CORE_STORE = 1,
    ICMP_DEBUG_CORE_MATCH = 2,
    ICMP_DEBUG_CORE_MISS  = 3,
    ICMP_DEBUG_RAN_STORE  = 4,
    ICMP_DEBUG_RAN_MATCH  = 5,
    ICMP_DEBUG_RAN_MISS   = 6,
};

struct icmp_id_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 id;      // ICMP identifier (from Echo Request/Reply)
} __attribute__((packed));

struct flow_id_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct teid_event_t {
    __u32 teid;
    __u8  source; // 0 = ingress, 1 = egress
    // NOTE: struct likely has padding; kernel BPF side must zero-init before perf output.
};

struct latency_event_t {
    __u32 teid;
    __u32 outer_dst_ip;
    __u64 latency_ns;
    __u64 sent_ns;
    __u64 acked_ns;
    __u8  mode;
    __u8  kind;
    __u16 reserved;
};

#define MAX_PACKET_DUMP_LEN 128

struct raw_packet_t {
    __u32 teid;
    __u16 len;
    __u8  data[MAX_PACKET_DUMP_LEN];
};

struct debug_event_t {
    __u32 teid;
    __u8  step;
    __u32 value;
};

struct flow_event_t {
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  direction;
    __u64 timestamp_ns;
    // NOTE: struct has padding; kernel BPF side must zero-init before perf output.
};

enum tcp_observation_type_t {
    TCP_OBS_CORE_DATA = 1,
    TCP_OBS_CORE_ACK  = 2,
    TCP_OBS_RAN_DATA  = 3,
    TCP_OBS_RAN_ACK   = 4,
    TCP_OBS_RESET     = 5,
};

struct tcp_observation_event_t {
    __u32 teid;
    __u32 outer_dst_ip;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 seq;
    __u32 ack_seq;
    __u32 seq_advance;
    __u32 payload_len;
    __u64 timestamp_ns;
    __u16 src_port;
    __u16 dst_port;
    __u8  direction;
    __u8  mode;
    __u8  flags;
    __u8  observation;
};

struct icmp_debug_event_t {
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 id;
    __u16 sequence;
    __u8  direction;
    __u8  mode;
    __u8  type;
    __u8  action;
};

#endif // __GTP_LATENCY_H__
