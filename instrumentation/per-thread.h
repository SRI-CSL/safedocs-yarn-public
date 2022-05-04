/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _MEMTRACE_PER_THREAD_H
#define _MEMTRACE_PER_THREAD_H

#include "dr_api.h"
#include <stdio.h>

typedef struct {
     reg_id_t addr_reg;
} write_info_t;

/* thread private log file and counter */
typedef struct {
     file_t log;
     FILE *logf;
     file_t write_log;
     FILE *write_logf;
     unsigned long long write_idx;
     app_pc bb_pc;
     // app_pc target;
     int syscall_flags;
     int syscall_fd;
     off_t syscall_offset;
     void *syscall_addr;
     // void *free_start;
     size_t syscall_len;
     int nested_log_on_count;
     int nested_log_off_count;
     bool syscall_mmap_logged;
     bool syscall_input_just_opened;
     bool log_on; /* whether log is currently writing entries to
		   * disk */
     /* true if last logging status message sent to log buffer is of
      * type SET_LOG_ON. May be a delay between this and log_on */
     bool logging_enabled;
     bool fn_filter_logging_enabled;
     bool file_offset_watchpoint_active;
     write_info_t write_regs;
     struct iovec *iovec;
     size_t iovec_len;
     char *dlopen_path;
} per_thread_mem_t;

#endif
