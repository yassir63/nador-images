/* GTPv1-U T-PDU parsing: outer IPv4, inner IPv4/IPv6; count inner IP bytes. */
struct tunnel_key {
    __u32 outer_dst_ip;
    __u32 teid;
};
static __always_inline __u16 read_be16(const __u8 *p) {
    return ((__u16)p[0] << 8) | p[1];
}
static __always_inline __u32 read_be32(const __u8 *p) {
    return ((__u32)p[0] << 24) | ((__u32)p[1] << 16) | ((__u32)p[2] << 8) | p[3];
}

/* Count a fragmented datagram once, from its first fragment's inner IP length.
 * Continuation fragments cannot identify a tunnel and must not add bytes again.
 * This accounts declared datagram bytes, not successful fragment reassembly. */
static __always_inline int parse_gtpu(struct __sk_buff *skb, struct tunnel_key *key, __u32 *bytes) {
    __u8 eth[14], ip[20], udp[8], gtp[8], optional[4], inner[40];
    if (bpf_skb_load_bytes(skb, 0, eth, 14) < 0 || read_be16(eth + 12) != 0x0800)
        return -1;
    if (bpf_skb_load_bytes(skb, 14, ip, 20) < 0 || (ip[0] >> 4) != 4 || ip[9] != 17)
        return -1;
    __u32 ihl = (ip[0] & 15) * 4, ip_length = read_be16(ip + 2);
    __u16 fragment = read_be16(ip + 6);
    int first_fragment = fragment & 0x2000;
    if (ihl < 20 || (fragment & 0x1fff) || ip_length < ihl + 16 ||
        14 + ip_length > skb->len)
        return -1;
    __u32 offset = 14 + ihl;
    if (bpf_skb_load_bytes(skb, offset, udp, 8) < 0)
        return -1;
    __u32 udp_length = read_be16(udp + 4);
    if ((read_be16(udp) != 2152 && read_be16(udp + 2) != 2152) || udp_length < 16)
        return -1;
    /* UDP length describes the whole datagram, not just its first fragment. */
    if (first_fragment ? (udp_length <= ip_length - ihl || (ip_length - ihl) % 8)
                       : udp_length > ip_length - ihl)
        return -1;
    offset += 8;
    if (bpf_skb_load_bytes(skb, offset, gtp, 8) < 0 || (gtp[0] & 0xf0) != 0x30 || gtp[1] != 255)
        return -1;
    __u32 end = offset + 8 + read_be16(gtp + 2);
    if (end > offset + udp_length - 8)
        return -1;
    __u32 header_end = end < 14 + ip_length ? end : 14 + ip_length;
    key->outer_dst_ip = read_be32(ip + 16);
    key->teid = read_be32(gtp + 4);
    offset += 8;
    __u8 next = 0;
    if (gtp[0] & 7) {
        if (offset + 4 > header_end || bpf_skb_load_bytes(skb, offset, optional, 4) < 0)
            return -1;
        next = (gtp[0] & 4) ? optional[3] : 0;
        offset += 4;
    }
#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (!next)
            break;
        __u8 length, next_type;
        if (bpf_skb_load_bytes(skb, offset, &length, 1) < 0 || !length)
            return -1;
        __u32 size = (__u32)length * 4;
        if (offset + size > header_end || bpf_skb_load_bytes(skb, offset + size - 1, &next_type, 1) < 0)
            return -1;
        next = next_type;
        offset += size;
    }
    if (next || offset + 20 > header_end || bpf_skb_load_bytes(skb, offset, inner, 20) < 0)
        return -1;
    if ((inner[0] >> 4) == 4) {
        *bytes = read_be16(inner + 2);
        if ((inner[0] & 15) < 5 || *bytes < (__u32)(inner[0] & 15) * 4 ||
            offset + (__u32)(inner[0] & 15) * 4 > header_end)
            return -1;
    } else if ((inner[0] >> 4) == 6) {
        if (offset + 40 > header_end || bpf_skb_load_bytes(skb, offset, inner, 40) < 0)
            return -1;
        *bytes = 40 + read_be16(inner + 4);
    } else
        return -1;
    return offset + *bytes <= end ? 0 : -1;
}
