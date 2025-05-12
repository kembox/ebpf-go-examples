//go:build ignore
#include "../../cilium/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 

#define MAX_FILENAME_LEN 127

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
   int pid;
   u8 filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF); 
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} events SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat,int dfd, struct filename *name) {
    struct event *task_info;
    task_info = bpf_ringbuf_reserve(&events,sizeof(struct event),0);
    if (!task_info) {
        return 0;
    }

    task_info->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel_str(&task_info->filename,sizeof(task_info->filename),(void *)BPF_CORE_READ(name,name));
    // bpf_printk("KPROBE ENTRY pid = %d, filename =%s\n",pid,filename);
    bpf_ringbuf_submit(&task_info,0);
    return 0;
}

/*
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_ret,long ret) {
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid %d, return code %d\n",pid,ret);
    return 0;
}
*/