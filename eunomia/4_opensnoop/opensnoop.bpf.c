//go:build ignore

#include "../../cilium/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const volatile int pid_target = 0;
struct event {
    int pid;
    // char filename[127];
    u8 filename[127];
    // char comm[256];
    u8 comm[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,1<<24);
    __type(value, struct event);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace__syscalls__sys_enter_openat(struct syscall_trace_enter *ctx) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events,sizeof(struct event),0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    if (pid_target && pid_target != e->pid ) {
        return false;
    }

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    bpf_core_read(&(e->comm), sizeof(e->comm),&task->comm);
    bpf_core_read(&(e->filename), sizeof(e->filename),&ctx->args[1]);

    bpf_ringbuf_submit(e,0);
    return 0;
}