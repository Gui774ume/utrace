/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _DEFS_H_
#define _DEFS_H_

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

__attribute__((always_inline)) static u64 load_func_id() {
    u64 func_id = 0;
    LOAD_CONSTANT("func_id", func_id);
    return func_id;
}

__attribute__((always_inline)) static u64 load_send_stack_trace() {
    u64 send_stack_trace = 0;
    LOAD_CONSTANT("send_stack_trace", send_stack_trace);
    return send_stack_trace;
}

__attribute__((always_inline)) static u64 load_filter_user_binary() {
    u64 filter_user_binary = 0;
    LOAD_CONSTANT("filter_user_binary", filter_user_binary);
    return filter_user_binary;
}

struct counter_t {
    u64 time;
    u64 count;
};

struct bpf_map_def SEC("maps/counters") counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct counter_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct start_ts_key_t {
    u64 func_id;
    u64 pid;
};

struct bpf_map_def SEC("maps/start_ts") start_ts = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct start_ts_key_t),
    .value_size = sizeof(u64),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

#define USER_STACK_TRACE 0
#define KERNEL_STACK_TRACE 1

struct bpf_map_def SEC("maps/lost_traces") lost_traces = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 2,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/stack_traces") stack_traces = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(u32),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
	.max_entries = 10240,
//	.map_flags = BPF_F_STACK_BUILD_ID,
    .pinning = 0,
    .namespace = "",
};

struct trace_event_t {
    u64 pid;
    u32 user_stack_id;
    u32 kernel_stack_id;
    u32 func_id;
};

struct bpf_map_def SEC("maps/trace_events") trace_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

#define PATH_MAX_LEN 350

struct path_t
{
    char filename[PATH_MAX_LEN];
};

struct bpf_map_def SEC("maps/binary_path") binary_path = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct path_t),
    .value_size = sizeof(u32),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/traced_pids") traced_pids = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

#endif
