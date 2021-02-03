/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _EXECVE_H_
#define _EXECVE_H_

struct sched_process_exec_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int data_loc_filename;
    pid_t pid;
    pid_t old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct sched_process_exec_args *ctx)
{
    unsigned short __offset = ctx->data_loc_filename & 0xFFFF;
    char *filename = (char *)ctx + __offset;
    struct path_t path = {};
    bpf_probe_read_str(&path.filename, PATH_MAX_LEN, filename);

    u32 *match = bpf_map_lookup_elem(&binary_path, &path.filename);
    if (match == NULL) {
        return 0;
    }

    // insert pid in list of traced pids
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 traced = 1;
    bpf_map_update_elem(&traced_pids, &pid, &traced, BPF_ANY);
    return 0;
};

#endif
