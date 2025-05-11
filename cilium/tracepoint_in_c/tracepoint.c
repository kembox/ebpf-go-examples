//go:build ignore

#include "../headers/common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} counting_map SEC(".maps");

// this struct is defined acording to the following format file:
// /sys/kernel/tracing/events/kmem/mm_page_alloc/format
/* A snippet 
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:unsigned long pfn;        offset:8;       size:8; signed:0;
        field:unsigned int order;       offset:16;      size:4; signed:0;
        field:gfp_t gfp_flags;  offset:20;      size:4; signed:0;
        field:int migratetype;  offset:24;      size:4; signed:1;
*/
struct alloc_info {
    /* the first 8 bytes is not allowed to read */
    unsigned long pad;

    unsigned long pfn;
    unsigned int order;
    unsigned int gfp_flags;
    int migratetype;
};

// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/tracing/events/kmem/mm_page_alloc
SEC("tracepoint/kmem/mm_page_alloc")
int mm_page_alloc(struct alloc_info *info) {
    u32 key = 0;
    u64 initval =1, *valp;
    valp = bpf_map_lookup_elem(&counting_map, &key);
    if (!valp) {
        bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp,1);
    return 0;
}

