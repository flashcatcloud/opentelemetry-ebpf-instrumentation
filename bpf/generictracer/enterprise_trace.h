// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/trace_helpers.h>
#include <common/trace_parent.h>

static __always_inline void enterprise_client_trace(tp_info_t *tp) {
    tp->ts = bpf_ktime_get_ns();

    trace_key_t key = {};
    trace_key_from_pid_tid(&key);
    tp_info_pid_t *parent = find_parent_process_trace(&key);
    if (parent && parent->valid && valid_trace(parent->tp.trace_id) &&
        should_be_in_same_transaction(&parent->tp, tp)) {
        __builtin_memcpy(tp->trace_id, parent->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, parent->tp.span_id, sizeof(tp->parent_id));
        urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
        tp->flags = parent->tp.flags;
        return;
    }

    init_new_trace(tp);
}

static __always_inline void enterprise_server_trace(tp_info_t *tp, tp_info_pid_t *previous) {
    tp->ts = bpf_ktime_get_ns();

    trace_key_t key = {};
    trace_key_from_pid_tid(&key);
    tp_info_pid_t *parent = find_parent_process_trace(&key);
    if (parent && parent->valid && valid_trace(parent->tp.trace_id) &&
        should_be_in_same_transaction(&parent->tp, tp)) {
        __builtin_memcpy(previous, parent, sizeof(*previous));
        __builtin_memcpy(tp->trace_id, parent->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, parent->tp.span_id, sizeof(tp->parent_id));
        urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
        tp->flags = parent->tp.flags;
        return;
    }

    init_new_trace(tp);
}
