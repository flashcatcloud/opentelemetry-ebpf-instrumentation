// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/common.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <common/trace_helpers.h>

#include <generictracer/enterprise_trace.h>

#include <maps/server_traces.h>

#include <pid/pid.h>

typedef struct tuxedo_invocation {
    u64 start_monotime_ns;
    tp_info_t tp;
    unsigned char service[k_tuxedo_service_max_len];
} tuxedo_invocation_t;

typedef struct tuxedo_call_key {
    u32 pid;
    s32 descriptor;
} tuxedo_call_key_t;

typedef struct tuxedo_server_invocation {
    u64 start_monotime_ns;
    tp_info_t tp;
    tp_info_pid_t previous;
    unsigned char service[k_tuxedo_service_max_len];
} tuxedo_server_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, tuxedo_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tuxedo_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, tuxedo_call_key_t);
    __type(value, tuxedo_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tuxedo_pending_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tuxedo_reply_descriptors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, tuxedo_server_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tuxedo_server_invocations SEC(".maps");

static __always_inline int begin_tuxedo_call(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    tuxedo_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
    };
    enterprise_client_trace(&invocation.tp);
    bpf_probe_read_user_str(
        invocation.service, sizeof(invocation.service), (const void *)PT_REGS_PARM1(ctx));
    bpf_map_update_elem(&tuxedo_invocations, &id, &invocation, BPF_ANY);
    return 0;
}

static __always_inline void
emit_tuxedo_call(const tuxedo_invocation_t *invocation, s32 status, u8 async) {
    tuxedo_request_trace_t *event = events_ringbuf_reserve(sizeof(*event), 0);
    if (!event) {
        return;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->type = k_event_type_tuxedo_client;
    event->async = async;
    event->status = status;
    event->start_monotime_ns = invocation->start_monotime_ns;
    event->end_monotime_ns = bpf_ktime_get_ns();
    event->tp = invocation->tp;
    task_pid(&event->pid);
    __builtin_memcpy(event->service, invocation->service, sizeof(event->service));
    bpf_ringbuf_submit(event, get_flags());
}

static __always_inline int begin_tuxedo_server(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    tuxedo_server_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
    };
    enterprise_server_trace(&invocation.tp, &invocation.previous);
    bpf_probe_read_user_str(
        invocation.service, sizeof(invocation.service), (const void *)PT_REGS_PARM1(ctx));
    bpf_map_update_elem(&tuxedo_server_invocations, &id, &invocation, BPF_ANY);

    trace_key_t key = {};
    trace_key_from_pid_tid(&key);
    tp_info_pid_t active = {
        .tp = invocation.tp,
        .pid = pid_from_pid_tgid(id),
        .valid = 1,
        .req_type = k_event_type_tuxedo_server,
    };
    bpf_map_update_elem(&server_traces, &key, &active, BPF_ANY);
    return 0;
}

static __always_inline int finish_tuxedo_server(s32 status) {
    const u64 id = bpf_get_current_pid_tgid();
    tuxedo_server_invocation_t *invocation = bpf_map_lookup_elem(&tuxedo_server_invocations, &id);
    if (!invocation) {
        return 0;
    }

    tuxedo_request_trace_t *event = events_ringbuf_reserve(sizeof(*event), 0);
    if (event) {
        __builtin_memset(event, 0, sizeof(*event));
        event->type = k_event_type_tuxedo_server;
        event->status = status;
        event->start_monotime_ns = invocation->start_monotime_ns;
        event->end_monotime_ns = bpf_ktime_get_ns();
        event->tp = invocation->tp;
        task_pid(&event->pid);
        __builtin_memcpy(event->service, invocation->service, sizeof(event->service));
        bpf_ringbuf_submit(event, get_flags());
    }

    trace_key_t key = {};
    trace_key_from_pid_tid(&key);
    if (invocation->previous.valid) {
        bpf_map_update_elem(&server_traces, &key, &invocation->previous, BPF_ANY);
    } else {
        bpf_map_delete_elem(&server_traces, &key);
    }
    bpf_map_delete_elem(&tuxedo_server_invocations, &id);
    return 0;
}

SEC("uprobe/tuxedo-server:RUNSERVER")
int GUARDED_PROG(obi_uprobe_tuxedo_runserver, struct pt_regs *, ctx) {
    return begin_tuxedo_server(ctx);
}

SEC("uretprobe/tuxedo-server:RUNSERVER")
int GUARDED_PROG(obi_uretprobe_tuxedo_runserver, struct pt_regs *, ctx) {
    return finish_tuxedo_server(0);
}

SEC("uprobe/libtux.so:tpreturn")
int GUARDED_PROG(obi_uprobe_tpreturn, struct pt_regs *, ctx) {
    return finish_tuxedo_server((s32)PT_REGS_PARM1(ctx) != 0);
}

SEC("uprobe/libtux.so:tpforward")
int GUARDED_PROG(obi_uprobe_tpforward, struct pt_regs *, ctx) {
    return finish_tuxedo_server(0);
}

SEC("uprobe/libtux.so:tpcall")
int GUARDED_PROG(obi_uprobe_tpcall, struct pt_regs *, ctx) {
    return begin_tuxedo_call(ctx);
}

SEC("uretprobe/libtux.so:tpcall")
int GUARDED_PROG(obi_uretprobe_tpcall, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    tuxedo_invocation_t *invocation = bpf_map_lookup_elem(&tuxedo_invocations, &id);
    if (!invocation) {
        return 0;
    }
    emit_tuxedo_call(invocation, (s64)PT_REGS_RC(ctx) < 0, 0);
    bpf_map_delete_elem(&tuxedo_invocations, &id);
    return 0;
}

SEC("uprobe/libtux.so:tpacall")
int GUARDED_PROG(obi_uprobe_tpacall, struct pt_regs *, ctx) {
    return begin_tuxedo_call(ctx);
}

SEC("uretprobe/libtux.so:tpacall")
int GUARDED_PROG(obi_uretprobe_tpacall, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    tuxedo_invocation_t *invocation = bpf_map_lookup_elem(&tuxedo_invocations, &id);
    if (!invocation) {
        return 0;
    }

    const s32 descriptor = (s32)PT_REGS_RC(ctx);
    if (descriptor < 0) {
        emit_tuxedo_call(invocation, 1, 1);
    } else {
        const tuxedo_call_key_t key = {
            .pid = (u32)(id >> 32),
            .descriptor = descriptor,
        };
        bpf_map_update_elem(&tuxedo_pending_calls, &key, invocation, BPF_ANY);
    }
    bpf_map_delete_elem(&tuxedo_invocations, &id);
    return 0;
}

SEC("uprobe/libtux.so:tpgetrply")
int GUARDED_PROG(obi_uprobe_tpgetrply, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }
    const u64 descriptor_ptr = PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&tuxedo_reply_descriptors, &id, &descriptor_ptr, BPF_ANY);
    return 0;
}

SEC("uretprobe/libtux.so:tpgetrply")
int GUARDED_PROG(obi_uretprobe_tpgetrply, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    u64 *descriptor_ptr = bpf_map_lookup_elem(&tuxedo_reply_descriptors, &id);
    if (!descriptor_ptr) {
        return 0;
    }

    s32 descriptor = -1;
    bpf_probe_read_user(&descriptor, sizeof(descriptor), (const void *)*descriptor_ptr);
    const tuxedo_call_key_t key = {
        .pid = (u32)(id >> 32),
        .descriptor = descriptor,
    };
    tuxedo_invocation_t *invocation = bpf_map_lookup_elem(&tuxedo_pending_calls, &key);
    if (invocation) {
        emit_tuxedo_call(invocation, (s64)PT_REGS_RC(ctx) < 0, 1);
        bpf_map_delete_elem(&tuxedo_pending_calls, &key);
    }
    bpf_map_delete_elem(&tuxedo_reply_descriptors, &id);
    return 0;
}

SEC("uprobe/libtux.so:tpcancel")
int GUARDED_PROG(obi_uprobe_tpcancel, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }
    const tuxedo_call_key_t key = {
        .pid = (u32)(id >> 32),
        .descriptor = (s32)PT_REGS_PARM1(ctx),
    };
    bpf_map_delete_elem(&tuxedo_pending_calls, &key);
    return 0;
}
