//go:build ignore
#include "../../cilium/vmlinux.h" 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

struct event {
    //u8 , not char , otherwise we'll have problem converting []int8 to []byte in go user program
    u8 comm[TASK_COMM_LEN];
    u32 pid;
    u8 ret[MAX_LINE_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __type(value , struct event);
} events SEC(".maps");

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret,const void *ret) {
    struct event *e;
    if (!ret) {
        return 0;
    }

    //bpf_get_current_comm(e->comm,TASK_COMM_LEN);
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(e->ret,sizeof(e->ret),ret);
    e = bpf_ringbuf_reserve(&events,sizeof(e),0);
    if (!e) {
        return 0;
    }
    bpf_ringbuf_submit(e,0);
    return 0;
};

char LICENSE[] SEC("license") = "GPL";