//go:build ignore 

// From https://github.com/cilium/ebpf/blob/main/examples/headers/common.h
// It's instruct by -I ../headers folder at generate time https://github.com/cilium/ebpf/blob/main/examples/kprobe/main.go#L17
#include "../headers/common.h"
// This is the lightweight version of vmlinux.h
// #include "../vmlinux.h"

#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"

// Obligated license info
char __license[] SEC("license") = "Dual MIT/GPL";

// legacy map type
// Major downsize of this struct type is key and value type information is lost 
// Which is why it's replaced by BTF style maps
struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

// Define main program. 
// Start by section naming macro to signal compilier about program type and ELF section it should be in
SEC("kprobe/sys_execve")
int kprobe_execve() {
    u32 key = 0; 
    u64 initval = 1, *valp;
    valp = bpf_map_lookup_elem(&kprobe_map,&key);
    if (!valp) {
        bpf_map_update_elem(&kprobe_map,&key, &initval, BPF_ANY);
        return 0;
    }

    //Atomic add, C thing
    __sync_fetch_and_add(valp, 1);
    return 0;

}
