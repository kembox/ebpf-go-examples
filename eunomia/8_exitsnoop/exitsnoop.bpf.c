//go:build ignore

#include "../../cilium/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h> 

#define TASK_COMM_LEN 16

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    u8 comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} rb SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    pid_t pid, ppid, tid;
    struct event *e;
    struct task_struct *task;

    u64 id, start_time=0;

    id = bpf_get_current_pid_tgid();
    task = (struct task_struct *)bpf_get_current_task();
    pid = id >> 32;
    tid = (u32)id;

    // Ignore thread exits. We care about process only
    if ( pid != tid ) {
        return 0;
    }
    ppid = BPF_CORE_READ(task,real_parent,pid);
    start_time = BPF_CORE_READ(task,start_time);

    e = bpf_ringbuf_reserve(&rb, sizeof(e),0);
    if (!e) {
        return 1;
    }

    e->duration_ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid = ppid;
    bpf_get_current_comm(e->comm,sizeof(e->comm));
    // Get the last 8 bit for exit_code only
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
