struct observation {
    __u64 ns;
    __u64 hash_a;
    __u64 hash_b;
    __u32 dst;
    __u32 teid;
    __u8 protocol;
    __u8 uplink;
    __u8 pad[6];
};
