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