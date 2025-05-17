//go:build ignore
#include "../../cilium/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_FILENAME_LEN 127
struct event {
    bool entry;
    long ret;
    int pid;
    u8 filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 8);
    __type(value, struct event);
} events SEC(".maps");

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat,int dfd, struct filename *name) {
    struct event *task_info;
    task_info = bpf_ringbuf_reserve(&events, sizeof(struct event),0);
    if (!task_info) {
        return 0;
    }

    task_info->entry = true;
    task_info->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel_str(&task_info->filename,sizeof(task_info->filename),name->name);
    bpf_ringbuf_submit(task_info,0);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit,int dfd, struct filename *name, long ret) {
    struct event *task_info;
    task_info = bpf_ringbuf_reserve(&events, sizeof(struct event),0);
    if (!task_info) {
        return 0;
    }

    task_info->entry = false;
    task_info->ret = ret;
    task_info->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel_str(&task_info->filename,sizeof(task_info->filename),name->name);
    bpf_ringbuf_submit(task_info,0);
    return 0;
}