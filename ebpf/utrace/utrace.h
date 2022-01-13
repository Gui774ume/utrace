/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UTRACE_H_
#define _UTRACE_H_

SEC("uprobe/utrace")
int uprobe_utrace(void *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 cookie = 0;

    // fetch pid cookie
    u32 *traced = bpf_map_lookup_elem(&traced_pids, &pid);
    if (traced == NULL) {
        return 0;
    }
    cookie = *traced;

    // hits counter
    u32 func_id = load_func_id();
    struct counter_t *counter = bpf_map_lookup_elem(&counters, &func_id);
    if (counter == NULL) {
        // should never happen, the list of traced functions is known
        return 0;
    }
    __sync_fetch_and_add(&counter->count, 1);

    // store entry timestamp
    struct start_ts_key_t key = {
        .func_id = func_id,
        .pid = bpf_get_current_pid_tgid(),
    };
    bpf_map_update_elem(&start_ts, &key, &now, BPF_ANY);

    // fetch stack trace
    u32 send_stack_trace = load_send_stack_trace();
    if (send_stack_trace) {
        struct trace_event_t evt = {};
        evt.pid = key.pid;
        evt.func_id = key.func_id;
        evt.cookie = cookie;
        evt.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK | BPF_F_REUSE_STACKID);

        u32 cpu = bpf_get_smp_processor_id();
        int ret = bpf_perf_event_output(ctx, &trace_events, cpu, &evt, sizeof(evt));
        if (ret != 0) {
            u32 lost_key = USER_STACK_TRACE;
            u64 *lost = bpf_map_lookup_elem(&lost_traces, &lost_key);
            if (lost != NULL) {
                __sync_fetch_and_add(lost, 1);
            }
        }
    }
    return 0;
};

SEC("uretprobe/utrace")
int uretprobe_utrace(void *ctx)
{
    u64 now = bpf_ktime_get_ns();

    // hits counter
    u32 func_id = load_func_id();
    struct counter_t *counter = bpf_map_lookup_elem(&counters, &func_id);
    if (counter == NULL) {
        // should never happen, the list of traced functions is known
        return 0;
    }

    // fetch start ts and compute latency
    struct start_ts_key_t key = {
        .func_id = load_func_id(),
        .pid = bpf_get_current_pid_tgid(),
    };
    u64 *ts = bpf_map_lookup_elem(&start_ts, &key);
    if (ts == NULL) {
        return 0;
    }
    __sync_fetch_and_add(&counter->time, now - *ts);

    return 0;
};

SEC("kprobe/utrace")
int kprobe_utrace(void *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 cookie = 0;

    // check if a filter should be applied on the process that made the call
    u32 filter_user_binary = load_filter_user_binary();
    if (filter_user_binary) {
        // check if this pid is traced
        u32 *traced = bpf_map_lookup_elem(&traced_pids, &pid);
        if (traced == NULL) {
            return 0;
        }
        cookie = *traced;
    }

    // hits counter
    u32 func_id = load_func_id();
    struct counter_t *counter = bpf_map_lookup_elem(&counters, &func_id);
    if (counter == NULL) {
        // should never happen, the list of traced functions is known
        return 0;
    }
    __sync_fetch_and_add(&counter->count, 1);

    // store entry timestamp
    struct start_ts_key_t key = {
        .func_id = func_id,
        .pid = pid_tgid,
    };
    bpf_map_update_elem(&start_ts, &key, &now, BPF_ANY);

    // fetch stack trace
    u32 send_stack_trace = load_send_stack_trace();
    if (send_stack_trace) {
        struct trace_event_t evt = {};
        evt.pid = key.pid;
        evt.func_id = key.func_id;
        evt.cookie = cookie;
        evt.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);

        if (filter_user_binary) {
            evt.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
        }

        u32 cpu = bpf_get_smp_processor_id();
        int ret = bpf_perf_event_output(ctx, &trace_events, cpu, &evt, sizeof(evt));
        if (ret != 0) {
            u32 lost_key = KERNEL_STACK_TRACE;
            u64 *lost = bpf_map_lookup_elem(&lost_traces, &lost_key);
            if (lost != NULL) {
                __sync_fetch_and_add(lost, 1);
            }
            if (filter_user_binary) {
                lost_key = USER_STACK_TRACE;
                lost = bpf_map_lookup_elem(&lost_traces, &lost_key);
                if (lost != NULL) {
                    __sync_fetch_and_add(lost, 1);
                }
            }
        }
    }
    return 0;
};

SEC("kretprobe/utrace")
int kretprobe_utrace(void *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // check if a filter should be applied on the process that made the call
    u32 filter_user_binary = load_filter_user_binary();
    if (filter_user_binary) {
        // check if this pid is traced
        u32 *traced = bpf_map_lookup_elem(&traced_pids, &pid);
        if (traced == NULL) {
            return 0;
        }
    }

    // update latency
    u32 func_id = load_func_id();
    struct counter_t *counter = bpf_map_lookup_elem(&counters, &func_id);
    if (counter == NULL) {
        // should never happen, the list of traced functions is known
        return 0;
    }

    // fetch start ts and compute latency
    struct start_ts_key_t key = {
        .func_id = load_func_id(),
        .pid = pid_tgid,
    };
    u64 *ts = bpf_map_lookup_elem(&start_ts, &key);
    if (ts == NULL) {
        return 0;
    }
    __sync_fetch_and_add(&counter->time, now - *ts);

    return 0;
};

SEC("tracepoint/utrace")
int tracepoint_utrace(void *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 cookie = 0;

    // check if a filter should be applied on the process that made the call
    u32 filter_user_binary = load_filter_user_binary();
    if (filter_user_binary) {
        // check if this pid is traced
        u32 *traced = bpf_map_lookup_elem(&traced_pids, &pid);
        if (traced == NULL) {
            return 0;
        }
        cookie = *traced;
    }

    // hits counter
    u32 func_id = load_func_id();
    struct counter_t *counter = bpf_map_lookup_elem(&counters, &func_id);
    if (counter == NULL) {
        // should never happen, the list of traced functions is known
        return 0;
    }
    __sync_fetch_and_add(&counter->count, 1);

    // store entry timestamp
    struct start_ts_key_t key = {
        .func_id = func_id,
        .pid = pid_tgid,
    };
    bpf_map_update_elem(&start_ts, &key, &now, BPF_ANY);

    // fetch stack trace
    u32 send_stack_trace = load_send_stack_trace();
    if (send_stack_trace) {
        struct trace_event_t evt = {};
        evt.pid = key.pid;
        evt.func_id = key.func_id;
        evt.cookie = cookie;
        evt.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);

        if (filter_user_binary) {
            evt.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
        }

        u32 cpu = bpf_get_smp_processor_id();
        int ret = bpf_perf_event_output(ctx, &trace_events, cpu, &evt, sizeof(evt));
        if (ret != 0) {
            u32 lost_key = KERNEL_STACK_TRACE;
            u64 *lost = bpf_map_lookup_elem(&lost_traces, &lost_key);
            if (lost != NULL) {
                __sync_fetch_and_add(lost, 1);
            }
            if (filter_user_binary) {
                lost_key = USER_STACK_TRACE;
                lost = bpf_map_lookup_elem(&lost_traces, &lost_key);
                if (lost != NULL) {
                    __sync_fetch_and_add(lost, 1);
                }
            }
        }
    }
    return 0;
};

#endif
