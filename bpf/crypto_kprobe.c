//go:build ignore

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __always_inline int emit_crypto_event(const char *algo_ptr, __u32 etype) {
    if (!should_trace())
        return 0;

    struct crypto_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = bpf_get_current_cgroup_id();

    __u64 pid_tgid  = bpf_get_current_pid_tgid();
    e->pid          = pid_tgid >> 32;
    e->tid          = (__u32)pid_tgid;

    e->event_type   = etype;
    e->confidence   = CONFIDENCE_HIGH;

    bpf_probe_read_kernel_str(e->algo_name, sizeof(e->algo_name), algo_ptr);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/crypto_alloc_aead")
int kprobe_crypto_alloc_aead(struct pt_regs *ctx) {
    const char *alg_name = (const char *)PT_REGS_PARM1(ctx);
    return emit_crypto_event(alg_name, EVENT_KERNEL_CRYPTO_API);
}

SEC("kprobe/crypto_alloc_shash")
int kprobe_crypto_alloc_shash(struct pt_regs *ctx) {
    const char *alg_name = (const char *)PT_REGS_PARM1(ctx);
    return emit_crypto_event(alg_name, EVENT_KERNEL_CRYPTO_API);
}

SEC("kprobe/crypto_alloc_skcipher")
int kprobe_crypto_alloc_skcipher(struct pt_regs *ctx) {
    const char *alg_name = (const char *)PT_REGS_PARM1(ctx);
    return emit_crypto_event(alg_name, EVENT_KERNEL_CRYPTO_API);
}

/* Force BTF emission */
struct crypto_event *unused_event __attribute__((unused));

char _license[] SEC("license") = "GPL";