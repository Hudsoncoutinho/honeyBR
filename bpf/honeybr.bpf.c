#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct event_t {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    __u32 event_type;
    __s32 dport;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

enum {
    EVENT_EXECVE = 1,
    EVENT_OPENAT = 2,
    EVENT_CONNECT = 3,
};

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __u64 id;
    __u64 args[6];
};

static __always_inline void fill_base(struct event_t *e, __u32 event_type) {
    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (__u32)id;
    e->tgid = (__u32)(id >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->event_type = event_type;
    e->dport = -1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    fill_base(e, EVENT_EXECVE);
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    fill_base(e, EVENT_OPENAT);
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    fill_base(e, EVENT_CONNECT);

    struct sockaddr sa = {};
    const struct sockaddr *uaddr = (const struct sockaddr *)ctx->args[1];
    bpf_probe_read_user(&sa, sizeof(sa), uaddr);

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uaddr);
        e->dport = (__s32)bpf_ntohs(sin.sin_port);
    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), uaddr);
        e->dport = (__s32)bpf_ntohs(sin6.sin6_port);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
