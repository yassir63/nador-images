#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <json-c/json.h>

#include "gtp_latency.skel.h"
#include "gtp_latency.h"
#include "tcp_repeat.h"
#include "tcp_rtt_variation.h"

static volatile sig_atomic_t exiting = 0;

static int map_fd_teid_slice = -1;
static __u8 debug_match_enabled = 0;
static __u8 packet_pairing_enabled_runtime = 0;
static __u8 configured_probe_role = PROBE_ROLE_GNB;
static int packet_collector_fd = -1;
static struct sockaddr_storage packet_collector_addr;
static socklen_t packet_collector_addrlen = 0;
static const char *probe_pod_name = NULL;
static const char *probe_node_name = NULL;
static const char *probe_target_name = NULL;

#define MAX_SLICE_LABELS 2048
#define MAX_SLICE_LABEL_LEN 32
#define TCP_CORR_MAX_FLOWS 1024
#define TCP_CORR_WINDOW 2048
#define TCP_OBS_PERF_PAGES 256
#define TCP_CORR_SAMPLE_TTL_NS 5000000000ULL

struct slice_label_entry_t {
    __u32 teid;
    char slice[MAX_SLICE_LABEL_LEN];
};

static struct slice_label_entry_t slice_labels[MAX_SLICE_LABELS];
static int slice_label_count = 0;

struct tcp_corr_key_t {
    __u8 mode;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct tcp_corr_sample_t {
    __u64 timestamp_ns;
    __u32 outer_dst_ip;
    __u32 expected_ack;
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 seq;
    __u32 payload_len;
    __u16 src_port;
    __u16 dst_port;
    __u8 flags;
    __u8 active;
    __u8 repeated;
};

struct tcp_corr_flow_t {
    int in_use;
    struct tcp_corr_key_t key;
    __u64 last_seen_ns;
    __u32 next_slot;
    struct tcp_rtt_variation_state rtt_variation;
    struct tcp_corr_sample_t samples[TCP_CORR_WINDOW];
};

static struct tcp_corr_flow_t tcp_corr_flows[TCP_CORR_MAX_FLOWS];
static struct tcp_repeat_entry tcp_repeat_table[TCP_REPEAT_SLOTS];
static __u64 tcp_corr_last_flush_ns = 0;

struct tcp_corr_metric_totals_t {
    __u64 data_observed;
    __u64 ack_observed;
    __u64 rtt_emitted;
    __u64 pending_evicted_overwrite;
    __u64 pending_evicted_ttl;
    __u64 pending_evicted_flow_reuse;
    __u64 ack_no_match;
};

static struct tcp_corr_metric_totals_t tcp_corr_metrics_core = {};
static struct tcp_corr_metric_totals_t tcp_corr_metrics_ran = {};

// Globals used by cleanup/signal handler
static struct gtp_latency_bpf *skel = NULL;
static struct bpf_tc_hook hook = { .sz = sizeof(struct bpf_tc_hook) };
static struct bpf_tc_opts opts_ingress = { .sz = sizeof(struct bpf_tc_opts) };
static struct bpf_tc_opts opts_egress  = { .sz = sizeof(struct bpf_tc_opts) };
static const char *iface = NULL;
static int priority = 1;

static const char *latency_mode_name(__u8 mode) {
    switch (mode) {
        case LATENCY_MODE_CORE:
            return "core";
        case LATENCY_MODE_RAN:
            return "ran";
        case LATENCY_MODE_BOTH:
            return "both";
        default:
            return "unknown";
    }
}

static const char *latency_kind_name(__u8 kind) {
    switch (kind) {
        case LATENCY_KIND_TCP_ACK:
            return "tcp_ack";
        case LATENCY_KIND_ICMP_ECHO:
            return "icmp_echo";
        default:
            return "unknown";
    }
}

static const char *probe_role_name(__u8 role) {
    switch (role) {
        case PROBE_ROLE_GNB:
            return "gnb";
        case PROBE_ROLE_UPF:
            return "upf";
        default:
            return "unknown";
    }
}

static __u8 parse_latency_mode(const char *value) {
    if (strcasecmp(value, "core") == 0)
        return LATENCY_MODE_CORE;
    if (strcasecmp(value, "ran") == 0)
        return LATENCY_MODE_RAN;
    if (strcasecmp(value, "both") == 0 || strcasecmp(value, "e2e") == 0)
        return LATENCY_MODE_BOTH;

    return 0;
}

static __u8 parse_probe_role(const char *value) {
    if (strcasecmp(value, "gnb") == 0)
        return PROBE_ROLE_GNB;
    if (strcasecmp(value, "upf") == 0)
        return PROBE_ROLE_UPF;

    return 0;
}

static const char *icmp_debug_action_name(__u8 action) {
    switch (action) {
        case ICMP_DEBUG_CORE_STORE:
            return "core_store";
        case ICMP_DEBUG_CORE_MATCH:
            return "core_match";
        case ICMP_DEBUG_CORE_MISS:
            return "core_miss";
        case ICMP_DEBUG_RAN_STORE:
            return "ran_store";
        case ICMP_DEBUG_RAN_MATCH:
            return "ran_match";
        case ICMP_DEBUG_RAN_MISS:
            return "ran_miss";
        default:
            return "unknown";
    }
}

static const char *tcp_observation_name(__u8 observation) {
    switch (observation) {
        case TCP_OBS_CORE_DATA:
            return "core_data";
        case TCP_OBS_CORE_ACK:
            return "core_ack";
        case TCP_OBS_RAN_DATA:
            return "ran_data";
        case TCP_OBS_RAN_ACK:
            return "ran_ack";
        default:
            return "unknown";
    }
}

static const char *ip_proto_name(__u8 proto) {
    switch (proto) {
        case IPPROTO_TCP:
            return "tcp";
        case IPPROTO_UDP:
            return "udp";
        case IPPROTO_ICMP:
            return "icmp";
        default:
            return "unknown";
    }
}

static const char *mode_direction_name(__u8 mode) {
    switch (mode) {
        case LATENCY_MODE_CORE:
            return "uplink";
        case LATENCY_MODE_RAN:
            return "downlink";
        default:
            return "unknown";
    }
}

static __u64 monotonic_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static struct tcp_corr_metric_totals_t *tcp_corr_metrics_for_mode(__u8 mode) {
    switch (mode) {
        case LATENCY_MODE_CORE:
            return &tcp_corr_metrics_core;
        case LATENCY_MODE_RAN:
            return &tcp_corr_metrics_ran;
        default:
            return NULL;
    }
}

static void format_ipv4(__u32 ip, char *buf, size_t len) {
    snprintf(buf, len, "%u.%u.%u.%u",
             ip & 0xff, (ip >> 8) & 0xff,
             (ip >> 16) & 0xff, (ip >> 24) & 0xff);
}

static __u32 slice_numeric_id(const char *slice_label) {
    if (!slice_label || !slice_label[0])
        return 0;

    __u32 hash = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)slice_label; *p; p++) {
        hash ^= *p;
        hash *= 16777619u;
    }

    return hash ? hash : 1;
}

static void remember_slice_label(__u32 teid, const char *slice_label) {
    if (!slice_label || !slice_label[0])
        return;

    for (int i = 0; i < slice_label_count; i++) {
        if (slice_labels[i].teid == teid) {
            snprintf(slice_labels[i].slice, sizeof(slice_labels[i].slice), "%s", slice_label);
            return;
        }
    }

    if (slice_label_count >= MAX_SLICE_LABELS)
        return;

    slice_labels[slice_label_count].teid = teid;
    snprintf(slice_labels[slice_label_count].slice, sizeof(slice_labels[slice_label_count].slice), "%s", slice_label);
    slice_label_count++;
}

static const char *lookup_slice_label(__u32 teid, __u32 numeric_slice, char *fallback, size_t fallback_len) {
    for (int i = 0; i < slice_label_count; i++) {
        if (slice_labels[i].teid == teid)
            return slice_labels[i].slice;
    }

    snprintf(fallback, fallback_len, "%u", numeric_slice);
    return fallback;
}

static int tcp_seq_gte_user(__u32 lhs, __u32 rhs) {
    return (__s32)(lhs - rhs) >= 0;
}

static int tcp_seq_gt_user(__u32 lhs, __u32 rhs) {
    return (__s32)(lhs - rhs) > 0;
}

static int tcp_corr_key_equal(const struct tcp_corr_key_t *a, const struct tcp_corr_key_t *b) {
    return a->mode == b->mode &&
           a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port;
}

static void expire_tcp_corr_samples(struct tcp_corr_flow_t *flow, __u64 now_ns) {
    struct tcp_corr_metric_totals_t *metrics = tcp_corr_metrics_for_mode(flow->key.mode);

    for (int i = 0; i < TCP_CORR_WINDOW; i++) {
        if (!flow->samples[i].active)
            continue;
        if (now_ns >= flow->samples[i].timestamp_ns &&
            now_ns - flow->samples[i].timestamp_ns > TCP_CORR_SAMPLE_TTL_NS) {
            flow->samples[i].active = 0;
            if (metrics)
                metrics->pending_evicted_ttl++;
        }
    }
}

static int tcp_corr_flow_has_active_samples(const struct tcp_corr_flow_t *flow) {
    for (int i = 0; i < TCP_CORR_WINDOW; i++) {
        if (flow->samples[i].active)
            return 1;
    }
    return 0;
}

static int tcp_corr_flow_active_sample_count(const struct tcp_corr_flow_t *flow) {
    int count = 0;

    for (int i = 0; i < TCP_CORR_WINDOW; i++) {
        if (flow->samples[i].active)
            count++;
    }

    return count;
}

static struct tcp_corr_flow_t *lookup_tcp_corr_flow(const struct tcp_corr_key_t *key, __u64 now_ns, int create) {
    int free_index = -1;
    int reusable_index = -1;
    int oldest_index = -1;
    __u64 oldest_last_seen = 0;

    for (int i = 0; i < TCP_CORR_MAX_FLOWS; i++) {
        struct tcp_corr_flow_t *flow = &tcp_corr_flows[i];

        if (!flow->in_use) {
            if (free_index < 0)
                free_index = i;
            continue;
        }

        expire_tcp_corr_samples(flow, now_ns);
        if (!tcp_corr_flow_has_active_samples(flow) &&
            now_ns >= flow->last_seen_ns &&
            now_ns - flow->last_seen_ns > TCP_CORR_SAMPLE_TTL_NS) {
            memset(flow, 0, sizeof(*flow));
            if (free_index < 0)
                free_index = i;
            continue;
        }

        if (tcp_corr_key_equal(&flow->key, key)) {
            flow->last_seen_ns = now_ns;
            return flow;
        }

        if (!tcp_corr_flow_has_active_samples(flow) && reusable_index < 0)
            reusable_index = i;

        if (oldest_index < 0 || flow->last_seen_ns < oldest_last_seen) {
            oldest_index = i;
            oldest_last_seen = flow->last_seen_ns;
        }
    }

    if (!create)
        return NULL;

    int index = free_index;
    if (index < 0)
        index = reusable_index;
    if (index < 0)
        index = oldest_index;
    if (index < 0)
        return NULL;

    if (tcp_corr_flows[index].in_use) {
        int active_count = tcp_corr_flow_active_sample_count(&tcp_corr_flows[index]);
        struct tcp_corr_metric_totals_t *metrics = tcp_corr_metrics_for_mode(tcp_corr_flows[index].key.mode);
        if (active_count > 0 && metrics)
            metrics->pending_evicted_flow_reuse += (__u64)active_count;
    }

    memset(&tcp_corr_flows[index], 0, sizeof(tcp_corr_flows[index]));
    tcp_corr_flows[index].in_use = 1;
    tcp_corr_flows[index].key = *key;
    tcp_corr_flows[index].last_seen_ns = now_ns;
    return &tcp_corr_flows[index];
}

static void cleanup(void) {
    if (!iface) {
        fprintf(stderr, "cleanup: iface is NULL\n");
        return;
    }

    fprintf(stderr, "\n🧼 Cleaning up eBPF filters on interface %s...\n", iface);

    hook.ifindex = if_nametoindex(iface);
    if (hook.ifindex == 0) {
        fprintf(stderr, "⚠️ cleanup: could not resolve ifindex for %s\n", iface);
        goto destroy_skel;
    }

    // Detach ingress
    hook.attach_point = BPF_TC_INGRESS;
    if (bpf_tc_detach(&hook, &opts_ingress) != 0) {
        fprintf(stderr, "⚠️ bpf_tc_detach failed on ingress. Trying tc fallback...\n");
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "tc filter del dev %s ingress prio %u", iface, (unsigned)priority);
        system(cmd);
    }

    // Detach egress
    hook.attach_point = BPF_TC_EGRESS;
    if (bpf_tc_detach(&hook, &opts_egress) != 0) {
        fprintf(stderr, "⚠️ bpf_tc_detach failed on egress. Trying tc fallback...\n");
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "tc filter del dev %s egress prio %u", iface, (unsigned)priority);
        system(cmd);
    }

destroy_skel:
    if (skel) {
        gtp_latency_bpf__destroy(skel);
        skel = NULL;
    }
    if (packet_collector_fd >= 0) {
        close(packet_collector_fd);
        packet_collector_fd = -1;
    }

    fprintf(stderr, "✅ Cleanup complete.\n");
}

static void sig_handler(int signo) {
    (void)signo;
    exiting = 1;
    cleanup();
}

static void handle_teid_event(void *ctx, int cpu, void *data, __u32 size) {
    (void)ctx; (void)cpu; (void)size;
    const struct teid_event_t *evt = data;
    const char *src = (evt->source == 0) ? "INGRESS" : "EGRESS ";
    // printf("[%s] TEID: 0x%08x\n", src, evt->teid);
}

static void add_common_event_fields(json_object *root, __u32 teid, __u8 mode) {
    __u32 slice_id = 0;
    char teid_str[16];
    char slice_fallback[16];
    const char *slice_label;

    if (map_fd_teid_slice >= 0)
        bpf_map_lookup_elem(map_fd_teid_slice, &teid, &slice_id);

    snprintf(teid_str, sizeof(teid_str), "0x%08x", teid);
    slice_label = lookup_slice_label(teid, slice_id, slice_fallback, sizeof(slice_fallback));

    json_object_object_add(root, "teid", json_object_new_string(teid_str));
    json_object_object_add(root, "slice", json_object_new_string(slice_label));
    json_object_object_add(root, "mode", json_object_new_string(latency_mode_name(mode)));
}

static void send_json_to_exporter(json_object *root) {
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/tmp/gtp_latency.sock", sizeof(addr.sun_path) - 1);

        const char *payload = json_object_to_json_string(root);
        (void)sendto(sock, payload, strlen(payload), 0, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
    }
}

static int init_packet_collector_socket(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    int fd = -1;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    rc = getaddrinfo(host, port, &hints, &result);
    if (rc != 0) {
        fprintf(stderr, "Could not resolve packet collector %s:%s: %s\n",
                host, port, gai_strerror(rc));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;

        memcpy(&packet_collector_addr, rp->ai_addr, rp->ai_addrlen);
        packet_collector_addrlen = rp->ai_addrlen;
        break;
    }

    freeaddrinfo(result);

    if (fd < 0) {
        fprintf(stderr, "Could not create UDP socket for packet collector %s:%s\n", host, port);
        return -1;
    }

    return fd;
}

static void send_json_to_packet_collector(json_object *root) {
    if (packet_collector_fd < 0 || packet_collector_addrlen == 0)
        return;

    const char *payload = json_object_to_json_string(root);
    (void)sendto(packet_collector_fd, payload, strlen(payload), 0,
                 (struct sockaddr *)&packet_collector_addr, packet_collector_addrlen);
}

static void emit_latency_json(__u32 teid, __u8 mode, __u8 kind, __u64 latency_ns, __u32 outer_dst_ip) {
    json_object *root = json_object_new_object();
    char endpoint[16];
    format_ipv4(outer_dst_ip, endpoint, sizeof(endpoint));
    json_object_object_add(root, "outer_dst_ip", json_object_new_string(endpoint));
    json_object_object_add(root, "event_type", json_object_new_string("latency"));
    add_common_event_fields(root, teid, mode);
    json_object_object_add(root, "latency_ns", json_object_new_int64((int64_t)latency_ns));
    json_object_object_add(root, "kind", json_object_new_string(latency_kind_name(kind)));
    send_json_to_exporter(root);
    json_object_put(root);
}

static void emit_tcp_path_signal(const struct tcp_observation_event_t *evt, const char *signal) {
    json_object *root = json_object_new_object();
    char endpoint[16];
    format_ipv4(evt->outer_dst_ip, endpoint, sizeof(endpoint));
    json_object_object_add(root, "event_type", json_object_new_string("tcp_path_signal"));
    json_object_object_add(root, "outer_dst_ip", json_object_new_string(endpoint));
    json_object_object_add(root, "signal", json_object_new_string(signal));
    json_object_object_add(root, "direction", json_object_new_string(
        evt->mode == LATENCY_MODE_CORE ? "uplink" : "downlink"));
    add_common_event_fields(root, evt->teid, evt->mode);
    send_json_to_exporter(root);
    json_object_put(root);
}

static void emit_tcp_rtt_variation(const struct tcp_corr_sample_t *sample, __u8 mode,
                                    uint64_t variation_ns) {
    json_object *root = json_object_new_object();
    char endpoint[16];
    format_ipv4(sample->outer_dst_ip, endpoint, sizeof(endpoint));
    json_object_object_add(root, "event_type", json_object_new_string("tcp_rtt_variation"));
    json_object_object_add(root, "outer_dst_ip", json_object_new_string(endpoint));
    json_object_object_add(root, "direction", json_object_new_string(mode_direction_name(mode)));
    json_object_object_add(root, "variation_ns", json_object_new_int64((int64_t)variation_ns));
    add_common_event_fields(root, sample->teid, mode);
    send_json_to_exporter(root);
    json_object_put(root);
}

static void emit_debug_json(__u32 teid, __u8 mode, const char *debug_proto, const char *debug_action) {
    json_object *root = json_object_new_object();
    json_object_object_add(root, "event_type", json_object_new_string("latency_debug"));
    add_common_event_fields(root, teid, mode);
    json_object_object_add(root, "debug_proto", json_object_new_string(debug_proto));
    json_object_object_add(root, "debug_action", json_object_new_string(debug_action));
    send_json_to_exporter(root);
    json_object_put(root);
}

static void emit_lost_json(const char *stream, __u64 lost_count) {
    json_object *root = json_object_new_object();
    json_object_object_add(root, "event_type", json_object_new_string("latency_lost"));
    json_object_object_add(root, "stream", json_object_new_string(stream));
    json_object_object_add(root, "lost_count", json_object_new_int64((int64_t)lost_count));
    send_json_to_exporter(root);
    json_object_put(root);
}

static void emit_tcp_corr_stats_json(__u8 mode, const struct tcp_corr_metric_totals_t *metrics) {
    json_object *root = json_object_new_object();

    json_object_object_add(root, "event_type", json_object_new_string("tcp_corr_stats"));
    json_object_object_add(root, "mode", json_object_new_string(latency_mode_name(mode)));
    json_object_object_add(root, "data_observed_count", json_object_new_int64((int64_t)metrics->data_observed));
    json_object_object_add(root, "ack_observed_count", json_object_new_int64((int64_t)metrics->ack_observed));
    json_object_object_add(root, "rtt_emitted_count", json_object_new_int64((int64_t)metrics->rtt_emitted));
    json_object_object_add(root, "pending_evicted_overwrite_count", json_object_new_int64((int64_t)metrics->pending_evicted_overwrite));
    json_object_object_add(root, "pending_evicted_ttl_count", json_object_new_int64((int64_t)metrics->pending_evicted_ttl));
    json_object_object_add(root, "pending_evicted_flow_reuse_count", json_object_new_int64((int64_t)metrics->pending_evicted_flow_reuse));
    json_object_object_add(root, "ack_no_match_count", json_object_new_int64((int64_t)metrics->ack_no_match));
    send_json_to_exporter(root);
    json_object_put(root);
}

static void flush_tcp_corr_metrics(int force) {
    __u64 now_ns = monotonic_time_ns();

    if (!force) {
        if (tcp_corr_last_flush_ns == 0) {
            tcp_corr_last_flush_ns = now_ns;
            return;
        }
        if (now_ns - tcp_corr_last_flush_ns < 1000000000ULL)
            return;
    }

    struct {
        __u8 mode;
        struct tcp_corr_metric_totals_t *metrics;
    } groups[] = {
        { LATENCY_MODE_CORE, &tcp_corr_metrics_core },
        { LATENCY_MODE_RAN,  &tcp_corr_metrics_ran  },
    };

    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
        struct tcp_corr_metric_totals_t *metrics = groups[i].metrics;
        if (!metrics->data_observed &&
            !metrics->ack_observed &&
            !metrics->rtt_emitted &&
            !metrics->pending_evicted_overwrite &&
            !metrics->pending_evicted_ttl &&
            !metrics->pending_evicted_flow_reuse &&
            !metrics->ack_no_match) {
            continue;
        }

        emit_tcp_corr_stats_json(groups[i].mode, metrics);
        memset(metrics, 0, sizeof(*metrics));
    }

    tcp_corr_last_flush_ns = now_ns;
}

static void emit_packet_rtt_sample_json(const struct tcp_corr_sample_t *sample, __u8 mode, __u64 latency_ns) {
    __u32 slice_id = 0;
    char teid_str[16];
    char slice_fallback[16];
    const char *slice_label;
    char src_ip[16];
    char dst_ip[16];
    json_object *root = json_object_new_object();

    if (!packet_pairing_enabled_runtime || packet_collector_fd < 0)
        return;

    if (map_fd_teid_slice >= 0)
        bpf_map_lookup_elem(map_fd_teid_slice, &sample->teid, &slice_id);

    snprintf(teid_str, sizeof(teid_str), "0x%08x", sample->teid);
    slice_label = lookup_slice_label(sample->teid, slice_id, slice_fallback, sizeof(slice_fallback));
    char endpoint[16];
    format_ipv4(sample->outer_dst_ip, endpoint, sizeof(endpoint));
    json_object_object_add(root, "outer_dst_ip", json_object_new_string(endpoint));
    format_ipv4(sample->src_ip, src_ip, sizeof(src_ip));
    format_ipv4(sample->dst_ip, dst_ip, sizeof(dst_ip));

    json_object_object_add(root, "event_type", json_object_new_string("packet_rtt_sample"));
    json_object_object_add(root, "observer_role", json_object_new_string(probe_role_name(configured_probe_role)));
    json_object_object_add(root, "teid", json_object_new_string(teid_str));
    json_object_object_add(root, "slice", json_object_new_string(slice_label));
    json_object_object_add(root, "mode", json_object_new_string(latency_mode_name(mode)));
    json_object_object_add(root, "logical_direction", json_object_new_string(mode_direction_name(mode)));
    json_object_object_add(root, "proto", json_object_new_string(ip_proto_name(IPPROTO_TCP)));
    json_object_object_add(root, "src_ip", json_object_new_string(src_ip));
    json_object_object_add(root, "dst_ip", json_object_new_string(dst_ip));
    json_object_object_add(root, "src_port", json_object_new_int((int)sample->src_port));
    json_object_object_add(root, "dst_port", json_object_new_int((int)sample->dst_port));
    json_object_object_add(root, "seq", json_object_new_int64((int64_t)sample->seq));
    json_object_object_add(root, "payload_len", json_object_new_int64((int64_t)sample->payload_len));
    json_object_object_add(root, "tcp_flags", json_object_new_int((int)sample->flags));
    json_object_object_add(root, "local_rtt_ns", json_object_new_int64((int64_t)latency_ns));

    if (probe_pod_name && *probe_pod_name)
        json_object_object_add(root, "observer_pod", json_object_new_string(probe_pod_name));
    if (probe_node_name && *probe_node_name)
        json_object_object_add(root, "observer_node", json_object_new_string(probe_node_name));
    if (probe_target_name && *probe_target_name)
        json_object_object_add(root, "observer_target", json_object_new_string(probe_target_name));

    send_json_to_packet_collector(root);
    json_object_put(root);
}

static void handle_latency_event(void *ctx, int cpu, void *data, __u32 size) {
    (void)ctx; (void)cpu; (void)size;

    const struct latency_event_t *evt = data;
    emit_latency_json(evt->teid, evt->mode, evt->kind, evt->latency_ns, evt->outer_dst_ip);
}

static void handle_flow_event(void *ctx, int cpu, void *data, __u32 size) {
    (void)ctx; (void)cpu; (void)size;

    if (!debug_match_enabled)
        return;

    const struct flow_event_t *evt = data;
    const char *dir = (evt->direction == 0) ? "INGRESS" : "EGRESS";

    if (evt->proto == 255) {
        printf("[FLOW-FAIL] %s TEID 0x%08x: failed to parse flow headers\n", dir, evt->teid);
        return;
    }

    char src_ip[16], dst_ip[16];
    snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u",
             evt->src_ip & 0xff, (evt->src_ip >> 8) & 0xff,
             (evt->src_ip >> 16) & 0xff, (evt->src_ip >> 24) & 0xff);

    snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u",
             evt->dst_ip & 0xff, (evt->dst_ip >> 8) & 0xff,
             (evt->dst_ip >> 16) & 0xff, (evt->dst_ip >> 24) & 0xff);

    printf("[FLOW] %s TEID 0x%08x @ %llu ns: %s:%u → %s:%u (proto %u)\n",
           dir, evt->teid, (unsigned long long)evt->timestamp_ns,
           src_ip, evt->src_port, dst_ip, evt->dst_port, evt->proto);
}

static void handle_tcp_observation_event(void *ctx, int cpu, void *data, __u32 size) {
    (void)ctx; (void)cpu;
    if (size < sizeof(struct tcp_observation_event_t))
        return;

    const struct tcp_observation_event_t *evt = data;
    if (evt->observation == TCP_OBS_RESET) {
        emit_tcp_path_signal(evt, "reset");
        return;
    }
    struct tcp_corr_key_t key = {};
    struct tcp_corr_flow_t *flow;
    struct tcp_corr_metric_totals_t *metrics = tcp_corr_metrics_for_mode(evt->mode);
    char src_ip[16], dst_ip[16];

    format_ipv4(evt->src_ip, src_ip, sizeof(src_ip));
    format_ipv4(evt->dst_ip, dst_ip, sizeof(dst_ip));

    if (evt->observation == TCP_OBS_CORE_DATA || evt->observation == TCP_OBS_RAN_DATA) {
        if (metrics)
            metrics->data_observed++;

        int repeated = 0;
        if (evt->payload_len && !(evt->flags & 0x06)) {
            struct tcp_repeat_key repeat_key = {
                .teid = evt->teid, .outer_dst_ip = evt->outer_dst_ip,
                .src_ip = evt->src_ip, .dst_ip = evt->dst_ip,
                .ports = ((__u32)evt->src_port << 16) | evt->dst_port,
                .seq = evt->seq, .payload_len = evt->payload_len, .mode = evt->mode,
            };
            repeated = tcp_repeat_observe(tcp_repeat_table, &repeat_key, evt->timestamp_ns);
            if (repeated)
                emit_tcp_path_signal(evt, "retransmission_candidate");
        }

        key.mode = evt->mode;
        key.src_ip = evt->src_ip;
        key.dst_ip = evt->dst_ip;
        key.src_port = evt->src_port;
        key.dst_port = evt->dst_port;

        flow = lookup_tcp_corr_flow(&key, evt->timestamp_ns, 1);
        if (!flow)
            return;

        if (repeated) {
            for (int i = 0; i < TCP_CORR_WINDOW; i++) {
                struct tcp_corr_sample_t *pending = &flow->samples[i];
                if (pending->active && pending->seq == evt->seq &&
                    pending->teid == evt->teid && pending->outer_dst_ip == evt->outer_dst_ip)
                    pending->repeated = 1;
            }
        }

        int slot_index = -1;
        for (int i = 0; i < TCP_CORR_WINDOW; i++) {
            if (!flow->samples[i].active) {
                slot_index = i;
                break;
            }
        }
        if (slot_index < 0)
            slot_index = flow->next_slot % TCP_CORR_WINDOW;

        if (flow->samples[slot_index].active && metrics)
            metrics->pending_evicted_overwrite++;

        flow->samples[slot_index].timestamp_ns = evt->timestamp_ns;
        flow->samples[slot_index].expected_ack = evt->seq + evt->seq_advance;
        flow->samples[slot_index].teid = evt->teid;
        flow->samples[slot_index].outer_dst_ip = evt->outer_dst_ip;
        flow->samples[slot_index].src_ip = evt->src_ip;
        flow->samples[slot_index].dst_ip = evt->dst_ip;
        flow->samples[slot_index].seq = evt->seq;
        flow->samples[slot_index].payload_len = evt->payload_len;
        flow->samples[slot_index].src_port = evt->src_port;
        flow->samples[slot_index].dst_port = evt->dst_port;
        flow->samples[slot_index].flags = evt->flags;
        flow->samples[slot_index].active = 1;
        flow->samples[slot_index].repeated = repeated;
        flow->next_slot = (slot_index + 1) % TCP_CORR_WINDOW;
        flow->last_seen_ns = evt->timestamp_ns;

        if (debug_match_enabled) {
            printf("[TCP-CORR] %s mode=%s action=store TEID 0x%08x %s:%u -> %s:%u "
                   "flags=0x%02x seq=%u ack=%u expected=%u payload=%u\n",
                   tcp_observation_name(evt->observation), latency_mode_name(evt->mode), evt->teid,
                   src_ip, evt->src_port, dst_ip, evt->dst_port,
                   evt->flags, evt->seq, evt->ack_seq, evt->seq + evt->seq_advance, evt->payload_len);
            emit_debug_json(evt->teid, evt->mode, "tcp",
                            evt->mode == LATENCY_MODE_CORE ? "core_store" : "ran_store");
        }
        return;
    }

    if (metrics)
        metrics->ack_observed++;

    key.mode = evt->mode;
    key.src_ip = evt->dst_ip;
    key.dst_ip = evt->src_ip;
    key.src_port = evt->dst_port;
    key.dst_port = evt->src_port;

    flow = lookup_tcp_corr_flow(&key, evt->timestamp_ns, 0);
    if (!flow) {
        if (metrics)
            metrics->ack_no_match++;
        if (debug_match_enabled) {
            printf("[TCP-CORR] %s mode=%s action=miss TEID 0x%08x %s:%u -> %s:%u "
                   "flags=0x%02x seq=%u ack=%u expected=0 payload=%u\n",
                   tcp_observation_name(evt->observation), latency_mode_name(evt->mode), evt->teid,
                   src_ip, evt->src_port, dst_ip, evt->dst_port,
                   evt->flags, evt->seq, evt->ack_seq, evt->payload_len);
            emit_debug_json(evt->teid, evt->mode, "tcp",
                            evt->mode == LATENCY_MODE_CORE ? "core_miss" : "ran_miss");
        }
        return;
    }

    int matched = 0;
    int best_index = -1;

    for (int i = 0; i < TCP_CORR_WINDOW; i++) {
        struct tcp_corr_sample_t *sample = &flow->samples[i];
        struct tcp_corr_sample_t *best_sample;

        if (!sample->active)
            continue;
        if (!tcp_seq_gte_user(evt->ack_seq, sample->expected_ack))
            continue;

        if (best_index < 0) {
            best_index = i;
            continue;
        }

        best_sample = &flow->samples[best_index];
        if (tcp_seq_gt_user(sample->expected_ack, best_sample->expected_ack) ||
            (sample->expected_ack == best_sample->expected_ack &&
             sample->timestamp_ns > best_sample->timestamp_ns)) {
            best_index = i;
        }
    }

    if (best_index >= 0) {
        struct tcp_corr_sample_t *sample = &flow->samples[best_index];
        __u64 latency_ns = evt->timestamp_ns - sample->timestamp_ns;

        emit_packet_rtt_sample_json(sample, evt->mode, latency_ns);
        /* Variation uses exact data ACKs only, without changing legacy RTT matching. */
        if (!sample->repeated && sample->payload_len && !(sample->flags & 0x07) &&
            !(evt->flags & 0x04) &&
            evt->ack_seq == sample->expected_ack && evt->timestamp_ns > sample->timestamp_ns) {
            uint64_t variation_ns;
            if (tcp_rtt_variation_observe(&flow->rtt_variation, sample->teid, sample->outer_dst_ip,
                                          evt->timestamp_ns, latency_ns, &variation_ns))
                emit_tcp_rtt_variation(sample, evt->mode, variation_ns);
        }
        matched = 1;
        if (metrics)
            metrics->rtt_emitted++;

        if (debug_match_enabled) {
            printf("[TCP-CORR] %s mode=%s action=match TEID 0x%08x %s:%u -> %s:%u "
                   "flags=0x%02x seq=%u ack=%u expected=%u payload=%u latency=%llu\n",
                   tcp_observation_name(evt->observation), latency_mode_name(evt->mode), sample->teid,
                   src_ip, evt->src_port, dst_ip, evt->dst_port,
                   evt->flags, evt->seq, evt->ack_seq, sample->expected_ack, evt->payload_len,
                   (unsigned long long)latency_ns);
            emit_debug_json(sample->teid, evt->mode, "tcp",
                            evt->mode == LATENCY_MODE_CORE ? "core_match" : "ran_match");
        }

        sample->active = 0;
    }

    flow->last_seen_ns = evt->timestamp_ns;

    if (!matched && debug_match_enabled) {
        printf("[TCP-CORR] %s mode=%s action=miss TEID 0x%08x %s:%u -> %s:%u "
               "flags=0x%02x seq=%u ack=%u expected=0 payload=%u\n",
               tcp_observation_name(evt->observation), latency_mode_name(evt->mode), evt->teid,
               src_ip, evt->src_port, dst_ip, evt->dst_port,
               evt->flags, evt->seq, evt->ack_seq, evt->payload_len);
        emit_debug_json(evt->teid, evt->mode, "tcp",
                        evt->mode == LATENCY_MODE_CORE ? "core_miss" : "ran_miss");
    }
    if (!matched && metrics)
        metrics->ack_no_match++;
}

static void handle_icmp_debug_event(void *ctx, int cpu, void *data, __u32 size) {
    (void)ctx; (void)cpu; (void)size;

    const struct icmp_debug_event_t *evt = data;
    const char *dir = (evt->direction == 0) ? "INGRESS" : "EGRESS";
    char src_ip[16], dst_ip[16];

    format_ipv4(evt->src_ip, src_ip, sizeof(src_ip));
    format_ipv4(evt->dst_ip, dst_ip, sizeof(dst_ip));

    printf("[ICMP-DEBUG] %s mode=%s action=%s TEID 0x%08x %s -> %s "
           "type=%u id=%u seq=%u\n",
           dir, latency_mode_name(evt->mode), icmp_debug_action_name(evt->action),
           evt->teid, src_ip, dst_ip, evt->type, evt->id, evt->sequence);

    json_object *root = json_object_new_object();
    json_object_object_add(root, "event_type", json_object_new_string("latency_debug"));
    add_common_event_fields(root, evt->teid, evt->mode);
    json_object_object_add(root, "debug_proto", json_object_new_string("icmp"));
    json_object_object_add(root, "debug_action", json_object_new_string(icmp_debug_action_name(evt->action)));
    send_json_to_exporter(root);
    json_object_put(root);
}

static void handle_tcp_observation_lost(void *ctx, int cpu, __u64 lost_cnt) {
    (void)ctx;

    fprintf(stderr,
            "[TCP-CORR] lost %llu tcp_observation events on cpu %d\n",
            (unsigned long long)lost_cnt, cpu);
    emit_lost_json("tcp_observation", lost_cnt);
}

int main(int argc, char **argv) {
    iface = (argc > 1) ? argv[1] : "n3";

    int prio = 1, hndl = 1;
    int argi = 2;
    __u8 latency_mode = LATENCY_MODE_CORE;
    __u8 probe_role = PROBE_ROLE_GNB;
    __u8 debug_match = 0;
    __u8 packet_correlation = 0;

    while (argi < argc) {
        if (strcmp(argv[argi], "--prio") == 0 && argi + 1 < argc) {
            prio = atoi(argv[++argi]);
        } else if (strcmp(argv[argi], "--handle") == 0 && argi + 1 < argc) {
            hndl = atoi(argv[++argi]);
        } else if (strcmp(argv[argi], "--mode") == 0 && argi + 1 < argc) {
            latency_mode = parse_latency_mode(argv[++argi]);
            if (latency_mode == 0) {
                fprintf(stderr, "Unknown latency mode: %s\n", argv[argi]);
                return 1;
            }
        } else if (strcmp(argv[argi], "--role") == 0 && argi + 1 < argc) {
            probe_role = parse_probe_role(argv[++argi]);
            if (probe_role == 0) {
                fprintf(stderr, "Unknown probe role: %s\n", argv[argi]);
                return 1;
            }
        } else if (strcmp(argv[argi], "--debug-match") == 0) {
            debug_match = 1;
        } else if (strcmp(argv[argi], "--packet-correlation") == 0 ||
                   strcmp(argv[argi], "--packet-pairing") == 0) {
            packet_correlation = 1;
        } else {
            break;
        }
        argi++;
    }

    priority = prio;
    debug_match_enabled = debug_match;
    packet_pairing_enabled_runtime = packet_correlation;
    configured_probe_role = probe_role;
    probe_pod_name = getenv("PROBE_POD");
    probe_node_name = getenv("PROBE_NODE");
    probe_target_name = getenv("PROBE_TARGET");

    hook.ifindex = if_nametoindex(iface);
    if (hook.ifindex == 0) {
        fprintf(stderr, "Could not find interface: %s\n", iface);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = gtp_latency_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    map_fd_teid_slice = bpf_map__fd(skel->maps.teid_slice_map);

    int map_fd_latency_config = bpf_map__fd(skel->maps.latency_config_map);
    if (map_fd_latency_config >= 0) {
        __u32 config_key = 0;
        struct latency_config_t cfg = {};
        cfg.mode = latency_mode;
        cfg.debug = debug_match;
        cfg.role = probe_role;
        if (bpf_map_update_elem(map_fd_latency_config, &config_key, &cfg, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to set latency config\n");
            cleanup();
            return 1;
        }
    }

    if (packet_correlation) {
        const char *collector_host = getenv("PACKET_PAIRER_HOST");
        const char *collector_port = getenv("PACKET_PAIRER_PORT");

        if (!collector_host || !collector_host[0])
            collector_host = getenv("PACKET_COLLECTOR_HOST");
        if (!collector_port || !collector_port[0])
            collector_port = getenv("PACKET_COLLECTOR_PORT");

        if (!collector_host || !collector_host[0])
            collector_host = "127.0.0.1";
        if (!collector_port || !collector_port[0])
            collector_port = "9201";

        packet_collector_fd = init_packet_collector_socket(collector_host, collector_port);
        if (packet_collector_fd < 0) {
            cleanup();
            return 1;
        }

        printf("Same-packet RTT forwarding enabled -> %s:%s\n", collector_host, collector_port);
    }

    // Parse TEID args: "UL:DL@slice" or "TEID@slice" (kept from your code)
    for (int i = argi; i < argc; i++) {
        char *arg = argv[i];
        char *at = strchr(arg, '@');
        char *colon = strchr(arg, ':');

        __u32 slice_id = 0;
        const char *slice_label = "";

        if (at) {
            *at = '\0';
            slice_label = at + 1;
            slice_id = slice_numeric_id(slice_label);
        }

        if (colon) {
            *colon = '\0';
            __u32 ul = strtoul(arg, NULL, 0);
            __u32 dl = strtoul(colon + 1, NULL, 0);

            bpf_map_update_elem(bpf_map__fd(skel->maps.teid_pair_map), &ul, &dl, BPF_ANY);
            printf("Tracking UL TEID 0x%08x → DL TEID 0x%08x", ul, dl);

            if (slice_id) {
                bpf_map_update_elem(bpf_map__fd(skel->maps.teid_slice_map), &ul, &slice_id, BPF_ANY);
                bpf_map_update_elem(bpf_map__fd(skel->maps.teid_slice_map), &dl, &slice_id, BPF_ANY);
                remember_slice_label(ul, slice_label);
                remember_slice_label(dl, slice_label);
                printf(" [Slice %s]", slice_label);
            }
            printf("\n");
        } else {
            __u32 teid = strtoul(arg, NULL, 0);
            __u8 one = 1;
            bpf_map_update_elem(bpf_map__fd(skel->maps.tracked_teids), &teid, &one, BPF_ANY);
            printf("Tracking single TEID 0x%08x", teid);

            if (slice_id) {
                bpf_map_update_elem(bpf_map__fd(skel->maps.teid_slice_map), &teid, &slice_id, BPF_ANY);
                remember_slice_label(teid, slice_label);
                printf(" [Slice %s]", slice_label);
            }
            printf("\n");
        }
    }

    // Attach ingress
    opts_ingress.handle = hndl;
    opts_ingress.priority = prio;
    opts_ingress.prog_fd = bpf_program__fd(skel->progs.tc_gtp_teid_ingress);

    hook.attach_point = BPF_TC_INGRESS;
    if (bpf_tc_attach(&hook, &opts_ingress)) {
        fprintf(stderr, "Failed to attach ingress program\n");
        cleanup();
        return 1;
    }

    // Attach egress
    opts_egress.handle = hndl + 1;
    opts_egress.priority = prio;
    opts_egress.prog_fd = bpf_program__fd(skel->progs.tc_gtp_teid_egress);

    hook.attach_point = BPF_TC_EGRESS;
    if (bpf_tc_attach(&hook, &opts_egress)) {
        fprintf(stderr, "Failed to attach egress program\n");
        cleanup();
        return 1;
    }

    // Perf buffers
    struct perf_buffer *pb_latency =
        perf_buffer__new(bpf_map__fd(skel->maps.latency_events), 8, handle_latency_event, NULL, NULL, NULL);

    struct perf_buffer *pb_teid =
        perf_buffer__new(bpf_map__fd(skel->maps.teid_events), 8, handle_teid_event, NULL, NULL, NULL);

    struct perf_buffer *pb_flow =
        perf_buffer__new(bpf_map__fd(skel->maps.flow_events), 8, handle_flow_event, NULL, NULL, NULL);

    struct perf_buffer *pb_tcp_observation =
        perf_buffer__new(
            bpf_map__fd(skel->maps.tcp_observation_events),
            TCP_OBS_PERF_PAGES,
            handle_tcp_observation_event,
            handle_tcp_observation_lost,
            NULL,
            NULL
        );

    struct perf_buffer *pb_icmp_debug = NULL;

    if (debug_match) {
        pb_icmp_debug =
            perf_buffer__new(bpf_map__fd(skel->maps.icmp_debug_events), 8, handle_icmp_debug_event, NULL, NULL, NULL);
    }

    if (!pb_latency || !pb_teid || !pb_flow || !pb_tcp_observation || (debug_match && !pb_icmp_debug)) {
        fprintf(stderr, "Failed to open perf buffers\n");
        cleanup();
        return 1;
    }

    printf("Monitoring GTP TEID + latency + flow on %s in %s mode as %s%s%s...\n",
           iface, latency_mode_name(latency_mode), probe_role_name(probe_role),
           debug_match ? " with match debug" : "",
           packet_correlation ? " with same-packet RTT forwarding" : "");

    while (!exiting) {
        perf_buffer__poll(pb_latency, 10);
        perf_buffer__poll(pb_teid, 10);
        perf_buffer__poll(pb_flow, 10);
        perf_buffer__poll(pb_tcp_observation, 10);
        if (pb_icmp_debug)
            perf_buffer__poll(pb_icmp_debug, 10);
        flush_tcp_corr_metrics(0);
    }

    flush_tcp_corr_metrics(1);
    cleanup();
    return 0;
}
