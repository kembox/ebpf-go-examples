## About struct pid and its namespace-aware member ##
Code from [latest version as of now](https://github.com/torvalds/linux/blob/master/include/linux/pid.h#L57-L74)
```
struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct {
		u64 ino;
		struct rb_node pidfs_node;
		struct dentry *stashed;
		struct pidfs_attr *attr;
	};
	/* lists of tasks that use this pid */
	struct hlist_head tasks[PIDTYPE_MAX];
	struct hlist_head inodes;
	/* wait queue for pidfd notifications */
	wait_queue_head_t wait_pidfd;
	struct rcu_head rcu;
	struct upid numbers[];
};
```

- `level` denotes in how many namespaces the process is visible ( this is the depth of the containing namespaces in namespace hierachy). 
- `upid` is used to get the id of `struct pid` as it is seen in particular namespace.
[Reference](https://students.mimuw.edu.pl/ZSO/Wyklady/13_CPUschedulers1/ProcessScheduling1.pdf)

- Finally got the point when libbpf maintainer said `following task_active_pid_ns` [here](https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.bpf.c#L66):
	- It just simply means the way we get pid namespace [here](https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.bpf.c#L71) by `bpf_core_read` is the same way [task_active_pid_ns](https://github.com/torvalds/linux/blob/v6.4/kernel/pid.c#L507) or actually [ns_of_pid](https://github.com/torvalds/linux/blob/master/include/linux/pid.h#L149) does

## BPF_PROG macro ##
- [BPF_PROG](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_PROG/)
 > The BPF_PROG macro makes it easier to write programs for program types that receive []u64 contexts such as BPF_PROG_TYPE_TRACING programs.

 > Conventionally with these program contexts, the arguments to the program are put in this array. So the first argument would be in ctx[0], the second in ctx[1]. It is up to the program author to cast them into their actual type.

 > allows you to write your program with a normal function signature, the macro will then do the casting for you.

- Example:
	- The other way to write `BPF_PROG_TYPE_RAW_TRACEPOINT` program is to use `struct bpf_raw_tracepoint_args *ctx` and cast it by ourselves like `(struct task_struct *)ctx->args[0]`, for example
	```
	SEC("raw_tp/sched_wakeup")
	int handle_sched_wakeup(struct bpf_raw_tracepoint_args *ctx) {
		...
		struct task_struct * t;
		t = ctx->args[0];
	}
	```
	- With `BPF_PROG` macro, the program looks more user friendly like:
	```
	SEC("raw_tp/sched_wakeup")
	int BPF_PROG(handle_sched_wakeup,struct task_struct *t) {
		// Can do something with task_struct right away
		pid_t pid;
		pid = BPF_CORE_READ(t,pid)
	}
	```
## How to check kernel events parameters ##
- [Reference](https://mozillazg.com/2022/05/ebpf-libbpf-raw-tracepoint-common-questions-en.html)
- From source code [include/trace/events](https://github.com/torvalds/linux/tree/master/include/trace/events)
	- Example with `sched_switch`: https://github.com/torvalds/linux/blob/master/include/trace/events/sched.h#L220-L227
- What's the difference between the source code above and the `format` info in `/sys/kernel/debug/tracing/events/sched/sched_switch/format` ?
	
	No difference , they are the same, read this [using the TRACE_EVENT macro lwm article](https://lwn.net/Articles/379903/) please

## A confusing statement in pid_namespace ##
- Understood the confusing `BPF_CORE_READ(upid.ns, ns.inum)`. Thanks to Gemini - I can't believe I said this :| 
	- The source of confusion is `ns` . The `upid.ns` results in a `pid_namespace` struct object, which contains a field call `ns` as well. The `ns` is a `ns_common` struct which really contains an `inum` field
	- I did see something off with this `BPF_CORE_READ` because if we're talking about the same ns here, it should be `BPF_CORE_READ(upid,ns,inum)` but couldn't figure it out. Ok I am stupid most of the time.

## BPF MAP TYPE ##
- BPF_MAP_TYPE_HASH: generic map - map 
- BPF_MAP_TYPE_CGROUP_ARRAY
	- From [oracle blog](https://blogs.oracle.com/linux/bpf-in-depth-communicating-with-userspace#:~:text=BPF%5FMAP%5FTYPE%5FCGROUP%5FARRAY%3A%20Array,index)

	> BPF_MAP_TYPE_CGROUP_ARRAY: Array map used to store cgroup fds in user-space for later use in BPF programs which call bpf_skb_under_cgroup() to check if skb is associated with the cgroup in the cgroup array at the specified index.
	- In our case it's used by [bpf_current_task_under_cgroup](https://docs.ebpf.io/linux/helper-function/bpf_current_task_under_cgroup/)
	- array map type