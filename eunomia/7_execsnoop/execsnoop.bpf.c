//go:build ignore
#include "../../cilium/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 32

struct event {
    int pid;
    int ppid;
    int uid;
    u8 filename[FILENAME_LEN];
    u8 comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<24);
    __type(value, struct event);
} events SEC(".maps");

SEC("tracepoint/syscall/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    pid_t tgid;
    struct event *event;
    struct task_struct *task;

    event = bpf_ringbuf_reserve(&events,sizeof(struct event),0);
    if (!event) {
        return 0;
    }

    uid_t uid = (u32)bpf_get_current_uid_gid();
    tgid  = bpf_get_current_pid_tgid() >> 32;
    event->pid = tgid;
    event->uid = uid;
    task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task,real_parent, tgid); //Macro to simplify BPF CO_RE read with pointer chasing involved
    char *filename_ptr = (char *)BPF_CORE_READ(ctx,args[0]);
    char *comm_ptr = (char *)BPF_CORE_READ(task,comm);
    bpf_core_read_str(event->comm,sizeof(event->comm),comm_ptr);
    bpf_core_read_user_str(event->filename,sizeof(event->filename),filename_ptr);

    bpf_ringbuf_submit(event,0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";