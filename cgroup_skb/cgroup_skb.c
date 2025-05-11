//go:build ignore

#include "../headers/common.h"

char __license[] SEC("license") = "Dual/MIT GPL";

/*
struct bpf_map_def SEC("maps") pkt_count = {
    .type = BPF_MAP_TYPE_ARRAY, 
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};
*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries,1);
} pkt_count SEC(".maps");

SEC("cgroup_skb/egress")
int count_egress_packet(struct __sk_buff *skb) {
    u32 key = 0;
    u64 init_val = 1;
    
    u64 *count = bpf_map_lookup_elem(&pkt_count, &key);

    if (!count) {
        bpf_map_update_elem(&pkt_count,&key,&init_val,BPF_ANY);
        return 1;
    }

    __sync_fetch_and_add(count,1);
    // When to use this ? 
    return 1;
}