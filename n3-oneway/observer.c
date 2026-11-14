#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include "observer.h"
#include "observer.skel.h"

static volatile sig_atomic_t done;
static void stop(int sig) { (void)sig; done = 1; }

static int emit(void *ctx, void *data, size_t size)
{
    (void)ctx;
    return size == sizeof(struct observation) &&
           fwrite(data, 1, size, stdout) == size ? 0 : -EIO;
}

int main(int argc, char **argv)
{
    if (argc != 8 && argc != 10) {
        fprintf(stderr, "usage: observer N3 GNB UPF PORT SAMPLE SEED_A SEED_B [N6 PEER]\n");
        return 2;
    }
    struct in_addr gnb, upf, peer;
    struct bpf_tc_hook hook = {.sz = sizeof(hook), .ifindex = if_nametoindex(argv[1])};
    struct bpf_tc_opts opts = {.sz = sizeof(opts), .priority = 1, .handle = 0x4e33};
    enum bpf_tc_attach_point points[] = {BPF_TC_INGRESS, BPF_TC_EGRESS};
    int n3 = hook.ifindex, n6 = argc == 10 ? (int)if_nametoindex(argv[8]) : n3;
    int err = 1, attached = 0;
    struct ring_buffer *ring = NULL;
    struct observer_bpf *obj = observer_bpf__open();
    if (!obj || !n3 || !n6 || inet_pton(AF_INET, argv[2], &gnb) != 1 ||
        inet_pton(AF_INET, argv[3], &upf) != 1)
        goto cleanup;
    obj->rodata->gnb = gnb.s_addr;
    obj->rodata->upf = upf.s_addr;
    obj->rodata->port = strtoul(argv[4], NULL, 10);
    obj->rodata->sample = strtoul(argv[5], NULL, 10);
    obj->rodata->seed_a = strtoull(argv[6], NULL, 16);
    obj->rodata->seed_b = strtoull(argv[7], NULL, 16);
    if (argc == 10) {
        if (inet_pton(AF_INET, argv[9], &peer) != 1)
            goto cleanup;
        obj->rodata->transit = 1;
        obj->rodata->peer = peer.s_addr;
        obj->rodata->n3_ifindex = n3;
        obj->rodata->n6_ifindex = n6;
        opts.handle = 0x4e36;
    }
    if (observer_bpf__load(obj))
        goto cleanup;
    ring = ring_buffer__new(bpf_map__fd(obj->maps.events), emit, NULL, NULL);
    if (!ring)
        goto cleanup;
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    signal(SIGPIPE, SIG_IGN);
    hook.attach_point = BPF_TC_INGRESS;
    int rc = bpf_tc_hook_create(&hook);
    if (rc && rc != -EEXIST)
        goto cleanup;
    while (attached < (n3 == n6 ? 2 : 4)) {
        hook.ifindex = attached < 2 ? n3 : n6;
        hook.attach_point = points[attached % 2];
        if (attached == 2) {
            rc = bpf_tc_hook_create(&hook);
            if (rc && rc != -EEXIST)
                goto cleanup;
        }
        opts.prog_fd = bpf_program__fd(attached % 2 ? obj->progs.n3_egress : obj->progs.n3_observe);
        opts.prog_id = 0;
        if (bpf_tc_attach(&hook, &opts))
            goto cleanup;
        attached++;
    }
    fprintf(stderr, "N3 observer attached on %s\n", argv[1]);
    __u64 last_loss = 0;
    while (!done) {
        rc = ring_buffer__poll(ring, 100);
        if (rc < 0 && rc != -EINTR)
            goto cleanup;
        __u32 zero = 0;
        struct observation status = {};
        if (!bpf_map_lookup_elem(bpf_map__fd(obj->maps.losses), &zero, &status.ns) &&
            status.ns != last_loss) {
            last_loss = status.ns;
            if (emit(NULL, &status, sizeof(status)))
                goto cleanup;
        }
        if (fflush(stdout))
            goto cleanup;
    }
    err = 0;
cleanup:
    if (err)
        fprintf(stderr, "N3 observer failed on %s\n", argv[1]);
    while (attached) {
        --attached;
        hook.ifindex = attached < 2 ? n3 : n6;
        hook.attach_point = points[attached % 2];
        opts.prog_fd = 0;
        opts.prog_id = 0;
        if (bpf_tc_detach(&hook, &opts))
            fprintf(stderr, "N3 observer filter detach failed (handle %#x)\n", opts.handle);
    }
    ring_buffer__free(ring);
    observer_bpf__destroy(obj);
    return err;
}
