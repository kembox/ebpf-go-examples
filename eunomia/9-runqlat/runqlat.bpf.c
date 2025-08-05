//go:build ignore

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>
#include "../../libbpf-tools/core_fixes.bpf.h"

#define MAX_ENTRIES 10240
#define TASK_RUNNING 0

const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile bool targ_tgid = false;

#define TASK_COMM_LEN 16
#define MAX_SLOTS 26

struct hist {
    __u32 slots[MAX_SLOTS];
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
    __uint(type ,BPF_MAP_TYPE_HASH);
    __uint(max_entires, MAX_ENTRIES);
    __type(key, u32);
    __type(value,u32);
} start SEC(".maps");

static struct hist zero;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct hist);
} hists SEC(".maps");

static int trace_enqueue(u32 tgid, u32 pid) {
    u64 ts;
    if (!pid) {
        return 0;
    }

    if (targ_tgid && targ_tgid != tgid) {
        return 0;
    }
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts,BPF_ANY);
    return 0;
}

static unsigned int pid_namespace(struct task_struct *task) {
    struct pid *pid;
    unsigned int level;
    struct upid upid;
    unsigned int inum;

    pid = BPF_CORE_READ(task,thread_pid);
    level = BPF_CORE_READ(pid, level);
    bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
    inum = BPF_CORE_READ(upid.ns, ns.inum);
    return inum;
}

static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next) {
    struct hist *histp;
    u64 *tsp, slot;
    u32 pid, hkey;
    s64 delta; // just long long int type
    
    if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) {
        return 0;
    }

    if (get_task_state(prev) == TASK_RUNNING) {
        trace_enqueue(BPF_CORE_READ(prev,tgid),BPF_CORE_READ(prev,pid));
    }

    pid = BPF_CORE_READ(next, pid);

    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp) {
        return 0;
    }

    delta = bpf_ktime_get_ns() - *tsp;
    if ( delta < 0) {
        goto cleanup;
    }

    if (targ_per_process) {
        hkey = BPF_CORE_READ(next, tgid);
    } else if (targ_per_thread) {
        hkey = BPF_CORE_READ(next, pid);
    } else if {targ_per_pidns} {
        hkey = pid_namespace(next);
    } else
        hkey = -1;

}