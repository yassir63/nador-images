#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>

#ifndef CONFIG_NET_NS
#error Network namespace attribution requires CONFIG_NET_NS
#endif

struct drop_key { u64 netns; u32 ifindex; u32 reason; u32 location; };
BPF_HASH(counts, struct drop_key, u64, @CAPACITY@);
BPF_ARRAY(diagnostics, u64, 2);

static __always_inline void diag(u32 i) {
    u64 *v = diagnostics.lookup(&i);
    if (v) __sync_fetch_and_add(v, 1);
}

TRACEPOINT_PROBE(skb, kfree_skb) {
    diag(0);
    struct drop_key key = {};
    key.reason = (u32)args->reason;
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    struct net_device *dev = 0;
    struct net *net = 0;
    int ifindex = 0;
    u32 inum = 0;
    if (!skb) { key.location = 1; goto count; }
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev)) {
        key.location = 5; goto count;
    }
    if (!dev) { key.location = 2; goto count; }
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex)) {
        key.location = 5; goto count;
    }
    if (ifindex <= 0) { key.location = 3; goto count; }
    key.ifindex = ifindex;
    if (bpf_probe_read_kernel(&net, sizeof(net), &dev->nd_net.net)) {
        key.location = 5; goto count;
    }
    if (!net) { key.location = 4; goto count; }
    if (bpf_probe_read_kernel(&inum, sizeof(inum), &net->ns.inum)) {
        key.location = 5; goto count;
    }
    if (!inum) { key.location = 4; goto count; }
    key.netns = inum;
count: ;
    u64 zero = 0;
    u64 *value = counts.lookup_or_try_init(&key, &zero);
    if (!value) { diag(1); return 0; }
    __sync_fetch_and_add(value, 1);
    return 0;
}
