//go:build ignore
// To avoid error like this: C source files not allowed when not using cgo or SWIG: uretprobe.c

#include "../headers/common.h"
#include "../headers/bpf_tracing.h"
// When to include bpf_tracing.sh ?

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u8 line[80];
};

struct {
    __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    // Why this type ? 
    __type(value, struct event);
} events SEC(".maps");

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx) {
    struct event event;

    event.pid = bpf_get_current_pid_tgid();
    bpf_probe_read(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));
    // PT_REGS_RC
    // To easily get return code for `struct pt_regs` style context
    // Architect dependent, need to pass ARCH info while compiling

    bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,&event,sizeof(event));
    return 0;
}