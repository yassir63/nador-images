#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "observer.h"

const volatile __u32 gnb, upf, sample = 16;
const volatile __u32 peer;
const volatile __u32 n3_ifindex, n6_ifindex;
const volatile __u8 transit;
const volatile __u16 port;
const volatile __u64 seed_a, seed_b;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} losses SEC(".maps");

static __always_inline __u16 word(const __u8 *p)
{
    return ((__u16)p[0] << 8) | p[1];
}

static __always_inline void mix(struct observation *e, __u8 byte)
{
    e->hash_a = (e->hash_a ^ byte) * 1099511628211ULL;
    e->hash_b = (e->hash_b ^ byte) * 14029467366897019727ULL;
}

static __always_inline int observe(struct __sk_buff *skb, int ingress)
{
    struct observation e = {};
    __u8 eth[14], ip[20], udp[8], gtp[8], ip_inner[20], tcp[20], data[16];
    __u32 src, off, end, len, ihl, transport, payload, payload_len;
    e.ns = bpf_ktime_get_ns();
    if (skb->gso_segs > 1 ||
        bpf_skb_load_bytes(skb, 0, eth, sizeof(eth)) || word(eth + 12) != 0x0800 ||
        bpf_skb_load_bytes(skb, 14, ip, sizeof(ip)) || (ip[0] >> 4) != 4 ||
        (word(ip + 6) & 0x3fff))
        return TC_ACT_PIPE;
    __builtin_memcpy(&src, ip + 12, 4);
    __builtin_memcpy(&e.dst, ip + 16, 4);
    e.uplink = src == gnb && e.dst == upf;
    if (ip[9] != 17 || (!e.uplink && !(src == upf && e.dst == gnb))) {
        if (!transit || (src != peer && e.dst != peer))
            return TC_ACT_PIPE;
        e.pad[0] = 1;
        e.uplink = e.dst == peer;
        e.dst = 0;
        off = 14;
        end = 14 + word(ip + 2);
        if (end > skb->len)
            return TC_ACT_PIPE;
        goto inner;
    }
    ihl = (ip[0] & 15) * 4;
    off = 14 + ihl;
    if (ihl < 20 || bpf_skb_load_bytes(skb, off, udp, sizeof(udp)) ||
        (word(udp) != 2152 && word(udp + 2) != 2152))
        return TC_ACT_PIPE;
    off += 8;
    if (bpf_skb_load_bytes(skb, off, gtp, sizeof(gtp)) ||
        (gtp[0] & 0xf0) != 0x30 || gtp[1] != 255)
        return TC_ACT_PIPE;
    end = off + 8 + word(gtp + 2);
    if (end > skb->len || end > 14 + word(ip + 2) ||
        word(udp + 4) < 16 + word(gtp + 2))
        return TC_ACT_PIPE;
    __builtin_memcpy(&e.teid, gtp + 4, 4);
    e.teid = bpf_ntohl(e.teid);
    off += 8;
    if (gtp[0] & 7) {
        __u8 opt[4], next;
        if (off + 4 > end || bpf_skb_load_bytes(skb, off, opt, sizeof(opt)))
            return TC_ACT_PIPE;
        off += 4;
        next = (gtp[0] & 4) ? opt[3] : 0;
#pragma unroll
        for (int i = 0; i < 4; ++i) {
            __u8 units;
            if (!next)
                break;
            if (off >= end || bpf_skb_load_bytes(skb, off, &units, 1) || !units)
                return TC_ACT_PIPE;
            off += 4 * units;
            if (off > end || bpf_skb_load_bytes(skb, off - 1, &next, 1))
                return TC_ACT_PIPE;
        }
        if (next)
            return TC_ACT_PIPE;
    }
inner:
    if (transit && (skb->ifindex != (e.pad[0] ? n6_ifindex : n3_ifindex) ||
        ingress != (e.uplink != e.pad[0])))
        return TC_ACT_PIPE;
    if (off + 20 > end || bpf_skb_load_bytes(skb, off, ip_inner, sizeof(ip_inner)) ||
        (ip_inner[0] >> 4) != 4 || (word(ip_inner + 6) & 0x3fff))
        return TC_ACT_PIPE;
    ihl = (ip_inner[0] & 15) * 4;
    len = word(ip_inner + 2);
    e.protocol = ip_inner[9];
    if (ihl != 20 || off + len > end || (e.protocol != 6 && e.protocol != 17))
        return TC_ACT_PIPE;
    transport = e.protocol == 6 ? 20 : 8;
    if (len < ihl + transport ||
        bpf_skb_load_bytes(skb, off + ihl, tcp, transport) ||
        (port && port != word(tcp + (e.uplink ? 2 : 0))))
        return TC_ACT_PIPE;
    if (e.protocol == 6)
        transport = (tcp[12] >> 4) * 4;
    if (transport < (e.protocol == 6 ? 20 : 8) || len < ihl + transport)
        return TC_ACT_PIPE;
    if (transit && !e.pad[0]) {
        __u32 remote;
        if (e.uplink)
            __builtin_memcpy(&remote, ip_inner + 16, 4);
        else
            __builtin_memcpy(&remote, ip_inner + 12, 4);
        if (remote != peer)
            return TC_ACT_PIPE;
    }
    payload = off + ihl + transport;
    payload_len = len - ihl - transport;
    e.hash_a = seed_a;
    e.hash_b = seed_b;
    if (transit) {
        /* Do not hash IP addresses, ports or checksums changed by SNAT. */
        mix(&e, payload_len >> 8);
        mix(&e, payload_len & 255);
        if (e.protocol == 6) {
#pragma unroll
            for (int i = 4; i < 12; i++)
                mix(&e, tcp[i]);
            mix(&e, tcp[13]);
        }
    } else {
#pragma unroll
      for (int i = 0; i < 20; ++i) {
        if (i != 10 && i != 11)
            mix(&e, ip_inner[i]);
        if (e.protocol == 6 && i != 16 && i != 17)
            mix(&e, tcp[i]);
        else if (e.protocol == 17 && i < 6)
            mix(&e, tcp[i]);
      }
    }
    /* Constant-cost fingerprint: headers and at most 32 payload bytes. */
    if (payload_len) {
        __u32 first = payload_len >= 16 ? 16 : 1 + ((payload_len - 1) & 15);
        __builtin_memset(data, 0, sizeof(data));
        if (bpf_skb_load_bytes(skb, payload, data, first))
            return TC_ACT_PIPE;
#pragma unroll
        for (int i = 0; i < 16; ++i)
            mix(&e, data[i]);
    }
    if (payload_len > 16) {
        if (bpf_skb_load_bytes(skb, off + len - 16, data, sizeof(data)))
            return TC_ACT_PIPE;
#pragma unroll
        for (int i = 0; i < 16; ++i)
            mix(&e, data[i]);
    }
    if (sample && (e.hash_a ^ (e.hash_b >> 32)) % sample == 0 &&
        bpf_ringbuf_output(&events, &e, sizeof(e), 0)) {
        __u32 zero = 0;
        __u64 *count = bpf_map_lookup_elem(&losses, &zero);
        if (count)
            __sync_fetch_and_add(count, 1);
    }
    return TC_ACT_PIPE;
}

SEC("tc") int n3_observe(struct __sk_buff *skb) { return observe(skb, 1); }
SEC("tc") int n3_egress(struct __sk_buff *skb) { return observe(skb, 0); }
char LICENSE[] SEC("license") = "GPL";
