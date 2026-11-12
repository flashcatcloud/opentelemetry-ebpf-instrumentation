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
#include <common/scratch_mem.h>

#include <generictracer/enterprise_trace.h>

#include <pid/pid.h>

enum { k_db_oracle = 4 };

enum {
    k_oci_htype_svcctx = 3,
    k_oci_htype_server = 8,
    k_oci_attr_server = 6,
};

typedef struct oci_statement_key {
    u32 pid;
    u32 _pad;
    u64 statement;
} oci_statement_key_t;

typedef struct oci_sql_text {
    unsigned char sql[k_sql_max_len];
} oci_sql_text_t;

typedef struct oci_prepare_invocation {
    u64 statement_out;
    oci_sql_text_t text;
    u32 _pad;
} oci_prepare_invocation_t;

typedef struct oci_execute_invocation {
    u64 start_monotime_ns;
    u64 statement;
    u64 service_context;
    tp_info_t tp;
} oci_execute_invocation_t;

typedef struct oci_handle_key {
    u32 pid;
    u32 _pad;
    u64 handle;
} oci_handle_key_t;

typedef struct oci_server_attach_invocation {
    u64 server;
    unsigned char connect[k_sql_hostname_max_len];
} oci_server_attach_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, oci_statement_key_t);
    __type(value, oci_sql_text_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} oci_statements SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, oci_prepare_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} oci_prepare_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, oci_execute_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} oci_execute_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, oci_handle_key_t);
    __type(value, unsigned char[k_sql_hostname_max_len]);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} oci_server_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, oci_handle_key_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} oci_service_servers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, oci_server_attach_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} oci_server_attach_invocations SEC(".maps");

SCRATCH_MEM_TYPED(oci_server_attach, oci_server_attach_invocation_t)

SCRATCH_MEM_TYPED(oci_prepare, oci_prepare_invocation_t)

static __always_inline oci_handle_key_t oci_handle_key(u64 handle) {
    return (oci_handle_key_t){
        .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
        .handle = handle,
    };
}

SEC("uprobe/libclntsh.so:OCIServerAttach")
int GUARDED_PROG(obi_uprobe_oci_server_attach, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    oci_server_attach_invocation_t *invocation = oci_server_attach_mem();
    if (!invocation) {
        return 0;
    }
    __builtin_memset(invocation, 0, sizeof(*invocation));
    invocation->server = PT_REGS_PARM1(ctx);
    const void *connect = (const void *)PT_REGS_PARM3(ctx);
    const s32 connect_len = (s32)PT_REGS_PARM4(ctx);
    if (connect) {
        if (connect_len > 0) {
            u64 safe_len = (u64)connect_len;
            if (safe_len >= sizeof(invocation->connect)) {
                safe_len = sizeof(invocation->connect) - 1;
            }
            bpf_probe_read_user(invocation->connect, safe_len, connect);
        } else {
            bpf_probe_read_user_str(invocation->connect, sizeof(invocation->connect), connect);
        }
    }
    bpf_map_update_elem(&oci_server_attach_invocations, &id, invocation, BPF_ANY);
    return 0;
}

SEC("uretprobe/libclntsh.so:OCIServerAttach")
int GUARDED_PROG(obi_uretprobe_oci_server_attach, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    oci_server_attach_invocation_t *invocation =
        bpf_map_lookup_elem(&oci_server_attach_invocations, &id);
    if (!invocation) {
        return 0;
    }
    if ((s64)PT_REGS_RC(ctx) >= 0 && invocation->server) {
        const oci_handle_key_t key = oci_handle_key(invocation->server);
        bpf_map_update_elem(&oci_server_connections, &key, invocation->connect, BPF_ANY);
    }
    bpf_map_delete_elem(&oci_server_attach_invocations, &id);
    return 0;
}

SEC("uprobe/libclntsh.so:OCIAttrSet")
int GUARDED_PROG(obi_uprobe_oci_attr_set, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id) || (u32)PT_REGS_PARM2(ctx) != k_oci_htype_svcctx ||
        (u32)PT_REGS_PARM5(ctx) != k_oci_attr_server) {
        return 0;
    }

    const u64 service_context = PT_REGS_PARM1(ctx);
    const u64 server = PT_REGS_PARM3(ctx);
    if (service_context && server) {
        const oci_handle_key_t key = oci_handle_key(service_context);
        bpf_map_update_elem(&oci_service_servers, &key, &server, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/libclntsh.so:OCIServerDetach")
int GUARDED_PROG(obi_uprobe_oci_server_detach, struct pt_regs *, ctx) {
    const oci_handle_key_t key = oci_handle_key(PT_REGS_PARM1(ctx));
    bpf_map_delete_elem(&oci_server_connections, &key);
    return 0;
}

SEC("uprobe/libclntsh.so:OCIHandleFree")
int GUARDED_PROG(obi_uprobe_oci_handle_free, struct pt_regs *, ctx) {
    const u32 handle_type = (u32)PT_REGS_PARM2(ctx);
    const oci_handle_key_t key = oci_handle_key(PT_REGS_PARM1(ctx));
    if (handle_type == k_oci_htype_server) {
        bpf_map_delete_elem(&oci_server_connections, &key);
    } else if (handle_type == k_oci_htype_svcctx) {
        bpf_map_delete_elem(&oci_service_servers, &key);
    }
    return 0;
}

static __always_inline int read_oci_sql(oci_sql_text_t *text, const void *sql, u64 len) {
    if (!sql || !len) {
        return -1;
    }

    __builtin_memset(text, 0, sizeof(*text));
    u64 safe_len = len;
    if (safe_len >= sizeof(text->sql)) {
        safe_len = sizeof(text->sql) - 1;
    }
    return bpf_probe_read_user(text->sql, safe_len, sql);
}

static __always_inline void store_oci_statement(u64 statement, const oci_sql_text_t *text) {
    if (!statement) {
        return;
    }
    const oci_statement_key_t key = {
        .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
        .statement = statement,
    };
    bpf_map_update_elem(&oci_statements, &key, text, BPF_ANY);
}

SEC("uprobe/libclntsh.so:OCIStmtPrepare2")
int GUARDED_PROG(obi_uprobe_oci_stmt_prepare2, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    oci_prepare_invocation_t *invocation = oci_prepare_mem();
    if (!invocation) {
        return 0;
    }
    __builtin_memset(invocation, 0, sizeof(*invocation));
    invocation->statement_out = PT_REGS_PARM2(ctx);
    if (read_oci_sql(
            &invocation->text, (const void *)PT_REGS_PARM4(ctx), (u64)PT_REGS_PARM5(ctx)) != 0) {
        return 0;
    }

    bpf_map_update_elem(&oci_prepare_invocations, &id, invocation, BPF_ANY);
    return 0;
}

SEC("uretprobe/libclntsh.so:OCIStmtPrepare2")
int GUARDED_PROG(obi_uretprobe_oci_stmt_prepare2, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    oci_prepare_invocation_t *invocation = bpf_map_lookup_elem(&oci_prepare_invocations, &id);
    if (!invocation) {
        return 0;
    }

    if ((s64)PT_REGS_RC(ctx) >= 0) {
        u64 statement = 0;
        bpf_probe_read_user(&statement, sizeof(statement), (const void *)invocation->statement_out);
        store_oci_statement(statement, &invocation->text);
    }
    bpf_map_delete_elem(&oci_prepare_invocations, &id);
    return 0;
}

SEC("uprobe/libclntsh.so:OCIStmtPrepare")
int GUARDED_PROG(obi_uprobe_oci_stmt_prepare, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    oci_prepare_invocation_t *invocation = oci_prepare_mem();
    if (!invocation || read_oci_sql(&invocation->text,
                                    (const void *)PT_REGS_PARM3(ctx),
                                    (u64)PT_REGS_PARM4(ctx)) != 0) {
        return 0;
    }
    store_oci_statement(PT_REGS_PARM1(ctx), &invocation->text);
    return 0;
}

SEC("uprobe/libclntsh.so:OCIStmtExecute")
int GUARDED_PROG(obi_uprobe_oci_stmt_execute, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    oci_execute_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .statement = PT_REGS_PARM2(ctx),
        .service_context = PT_REGS_PARM1(ctx),
    };
    enterprise_client_trace(&invocation.tp);
    bpf_map_update_elem(&oci_execute_invocations, &id, &invocation, BPF_ANY);
    return 0;
}

SEC("uretprobe/libclntsh.so:OCIStmtExecute")
int GUARDED_PROG(obi_uretprobe_oci_stmt_execute, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    oci_execute_invocation_t *invocation = bpf_map_lookup_elem(&oci_execute_invocations, &id);
    if (!invocation) {
        return 0;
    }

    sql_request_trace_t *event = events_ringbuf_reserve(sizeof(*event), 0);
    if (event) {
        __builtin_memset(event, 0, sizeof(*event));
        event->type = k_event_type_sql_client;
        event->sub_type = k_db_oracle;
        event->status = (s64)PT_REGS_RC(ctx) < 0;
        event->start_monotime_ns = invocation->start_monotime_ns;
        event->end_monotime_ns = bpf_ktime_get_ns();
        event->tp = invocation->tp;
        task_pid(&event->pid);

        const oci_statement_key_t key = {
            .pid = (u32)(id >> 32),
            .statement = invocation->statement,
        };
        const oci_sql_text_t *text = bpf_map_lookup_elem(&oci_statements, &key);
        if (text) {
            __builtin_memcpy(event->sql, text->sql, sizeof(event->sql));
        }
        const oci_handle_key_t service_key = oci_handle_key(invocation->service_context);
        const u64 *server = bpf_map_lookup_elem(&oci_service_servers, &service_key);
        if (server) {
            const oci_handle_key_t server_key = oci_handle_key(*server);
            const unsigned char *connect =
                bpf_map_lookup_elem(&oci_server_connections, &server_key);
            if (connect) {
                __builtin_memcpy(event->hostname, connect, sizeof(event->hostname));
            }
        }
        bpf_ringbuf_submit(event, get_flags());
    }

    bpf_map_delete_elem(&oci_execute_invocations, &id);
    return 0;
}

SEC("uprobe/libclntsh.so:OCIStmtRelease")
int GUARDED_PROG(obi_uprobe_oci_stmt_release, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }
    const oci_statement_key_t key = {
        .pid = (u32)(id >> 32),
        .statement = PT_REGS_PARM1(ctx),
    };
    bpf_map_delete_elem(&oci_statements, &key);
    return 0;
}
