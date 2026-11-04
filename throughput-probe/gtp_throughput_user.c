#include "gtp_throughput.skel.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct tunnel_key {
    uint32_t outer_dst_ip, teid;
};
struct tunnel_stats {
    uint64_t packets, bytes;
};
static volatile sig_atomic_t exiting;

/* Leave cleanup to the main loop so only our own TC filters are detached. */
static void stop(int signal_number) {
    (void)signal_number;
    exiting = 1;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: probe IFACE HANDLE PRIO endpoint|teid ...\n");
        return 1;
    }
    int rc = 1, cpus = libbpf_num_possible_cpus();
    if (cpus < 1)
        return 1;
    struct tunnel_stats *percpu = calloc(cpus, sizeof(*percpu));
    struct gtp_throughput_bpf *skel = gtp_throughput_bpf__open_and_load();
    if (!skel || !percpu) {
        free(percpu);
        return 1;
    }
    int tracked_fd = bpf_map__fd(skel->maps.tracked_tunnels);
    for (int i = 4; i < argc; i++) {
        char address[INET_ADDRSTRLEN], *sep = strchr(argv[i], '|'), *tail;
        if (!sep || sep - argv[i] >= INET_ADDRSTRLEN)
            goto finish;
        memcpy(address, argv[i], sep - argv[i]);
        address[sep - argv[i]] = 0;
        struct in_addr ip;
        unsigned long teid = strtoul(sep + 1, &tail, 0);
        if (inet_pton(AF_INET, address, &ip) != 1 || *tail || teid > UINT32_MAX)
            goto finish;
        struct tunnel_key key = {ntohl(ip.s_addr), (uint32_t)teid};
        uint8_t present = 1;
        if (bpf_map_update_elem(tracked_fd, &key, &present, BPF_ANY))
            goto finish;
    }
    struct bpf_tc_hook hook = {.sz = sizeof(hook),
                               .ifindex = if_nametoindex(argv[1]),
                               .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS};
    struct bpf_tc_opts opts = {.sz = sizeof(opts),
                               .handle = strtoul(argv[2], NULL, 10),
                               .priority = strtoul(argv[3], NULL, 10)};
    if (!hook.ifindex)
        goto finish;
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
        goto finish;
    hook.attach_point = BPF_TC_INGRESS;
    opts.prog_fd = bpf_program__fd(skel->progs.tc_gtp_ingress);
    if (bpf_tc_attach(&hook, &opts))
        goto finish;
    hook.attach_point = BPF_TC_EGRESS;
    /* libbpf fills prog_id on attach; it must be zero for the next request. */
    opts.prog_id = 0;
    opts.prog_fd = bpf_program__fd(skel->progs.tc_gtp_egress);
    if (bpf_tc_attach(&hook, &opts)) {
        hook.attach_point = BPF_TC_INGRESS;
        opts.prog_fd = 0;
        opts.prog_id = 0;
        bpf_tc_detach(&hook, &opts);
        goto finish;
    }
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    int stats_fd = bpf_map__fd(skel->maps.tunnel_stats);
    while (!exiting) {
        sleep(1);
        struct tunnel_key key, next, *previous = NULL;
        while (bpf_map_get_next_key(stats_fd, previous, &next) == 0) {
            key = next;
            previous = &key;
            if (bpf_map_lookup_elem(stats_fd, &key, percpu))
                continue;
            uint64_t packets = 0, bytes = 0;
            for (int cpu = 0; cpu < cpus; cpu++) {
                packets += percpu[cpu].packets;
                bytes += percpu[cpu].bytes;
            }
            struct in_addr ip = {htonl(key.outer_dst_ip)};
            char address[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip, address, sizeof(address));
            printf("{\"outer_dst_ip\":\"%s\",\"teid\":%u,\"packets\":%llu,\"bytes\":%llu}\n",
                   address, key.teid, (unsigned long long)packets, (unsigned long long)bytes);
        }
        fflush(stdout);
    }
    opts.prog_fd = 0;
    opts.prog_id = 0;
    hook.attach_point = BPF_TC_INGRESS;
    bpf_tc_detach(&hook, &opts);
    hook.attach_point = BPF_TC_EGRESS;
    bpf_tc_detach(&hook, &opts);
    rc = 0;
finish:
    if (rc)
        fprintf(stderr, "Throughput probe failed: %s\n", strerror(errno));
    gtp_throughput_bpf__destroy(skel);
    free(percpu);
    return rc;
}
