/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _MEMTRACE_LOGGING_H
#define _MEMTRACE_LOGGING_H
#include "dr_api.h"
#include "per-thread.h"
#include "recording-utils.h"
#include "drx.h"

/* Max number of mem_ref a buffer can have. It should be big enough
 * to hold all entries between clean calls.
 */
#define MAX_NUM_LOG_REFS 0x40000
/* The maximum size of buffer for holding log entries. */
#define LOG_BUF_SIZE (sizeof(log_entry_t) * MAX_NUM_LOG_REFS)


void set_logging(void *drcontext, bool enabled, app_pc pc, log_entry_t *log,
		 per_thread_mem_t *data);
void copy_log_entry_to_buf(void *drcontext, log_entry_t *entry);
void flush_log_buffer(void *drcontext, void *buf_base, size_t size);
void log_on_wrap_pre(void *wrapcxt, OUT void **user_data);
void log_off_wrap_pre(void *wrapcxt, OUT void **user_data);
void log_on_wrap_post(void *wrapcxt, void *user_data);
void log_off_wrap_post(void *wrapcxt, void *user_data);
void populate_call_log(app_pc instr_addr, app_pc target_addr, int kind,
		       void *context);

extern drx_buf_t *log_buffer;
extern const char *logdir;
#endif
