//go:build ignore
#include "../../cilium/vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct event {
    unsigned int pid;
    unsigned int tpid;
    int sig;
    int ret;
    u8 comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct event);
} values SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<24);
    __type(value, struct event);
} events SEC(".maps");

// `tpid` is the the PID of the process we want to kill - to pid
static int probe_entry(int tpid, int sig) {
    struct event event = {};
    __u64 pid_tgid;
    __u32 tid;
    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32)pid_tgid;
    event.pid = pid_tgid >> 32;
    event.tpid = tpid;
    bpf_get_current_comm(event.comm,sizeof(event.comm));
    bpf_map_update_elem(&values,&tid,&event,BPF_ANY);
    return 0;
}

static int probe_exit(void *ctx, int ret) {
    __u64 pid_tgid;
    __u32 tid;
    pid_tgid = bpf_get_current_pid_tgid();
    tid  = (__u32)pid_tgid;
    struct event *eventp = bpf_ringbuf_reserve(&events,sizeof(struct event),0);
    if (!eventp) {
        return 0;
    }

    eventp = bpf_map_lookup_elem(&values,&tid);
    if (!eventp) {
        return 0;
    }

    /*
    bpf_printk("PID %d (%s) sent signal %d ",
           eventp->pid, eventp->comm, eventp->sig);
    bpf_printk("to PID %d, ret = %d",
           eventp->tpid, ret);
    */
    bpf_ringbuf_submit(eventp,0);
    cleanup:
        bpf_map_delete_elem(&values,&tid);
        return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx) {
    pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];
    return probe_entry(tpid,sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx) {
    return probe_exit(ctx,ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
