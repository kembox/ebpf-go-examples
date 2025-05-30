//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_endian.h"
#include "../headers/bpf_tracing.h"

#define AF_INET 2
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        __u32 _;
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    short unsigned int skc_family;
};

struct sock {
    struct sock_common __sk_common;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<24);
    __type(value, struct event);
} events SEC(".maps");

struct event {
    u8 comm[16];
    __u16 sport;
    __u16 dport;
    __be32 saddr;
    __be32 daddr;
};

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
    if ( sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }

    struct event *tcp_info;
    tcp_info = bpf_ringbuf_reserve(&events,sizeof(struct event),0);
    if (!tcp_info) {
        return 0;
    }

    tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
    tcp_info->daddr = sk->__sk_common.skc_daddr;
    tcp_info->dport = sk->__sk_common.skc_dport;
    tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);

    bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);
    bpf_ringbuf_submit(tcp_info,0);
    return 0;
}