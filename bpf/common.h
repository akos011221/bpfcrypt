#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ALGO_NAME_LEN 64
#define TASK_COMM_LEN 16

/* Which detection method product the event */
enum event_type {
    EVENT_KERNEL_CRYPTO_API = 1,
    EVENT_PERF_COUNTER      = 2,
    EVENT_UPROBE            = 3,
    EVENT_HEURISTIC         = 4,
};

/* How confident is the detection */
enum confidence_level {
    CONFIDENCE_LOW    = 1,
    CONFIDENCE_MEDIUM = 2,
    CONFIDENCE_HIGH   = 3,
};

struct crypto_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tid;
    __u32 event_type;
    __u32 confidence;
    char algo_name[ALGO_NAME_LEN];
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

static __always_inline int should_trace() {
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid, &key);

    if (!target || *target == 0) {
        return 1;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    return pid == *target;
}

#endif /* __COMMON_H__ */