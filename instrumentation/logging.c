/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include "logging.h"
#include "mem-trace.h"
#include "prune.h"
#include "drmgr.h"
#include "drwrap.h"
#include <string.h>

drx_buf_t *log_buffer;
const char *logdir = NULL;

void
set_logging(void *drcontext, bool enabled, app_pc pc, log_entry_t *log,
	    per_thread_mem_t *data)
{
     int typ;
     if (enabled) {
	  typ = SET_LOG_ON;
     } else {
	  typ = SET_LOG_OFF;
     }
     data->logging_enabled = enabled;
     log->kind = typ;
     log->u.ins.pc = (void *) pc;
     copy_log_entry_to_buf(drcontext, log);
}

static byte *
reset_log_buffer(void *drcontext, byte *buf_base, size_t buf_size)
{
    flush_log_buffer(drcontext, buf_base, buf_size);
    drx_buf_set_buffer_ptr(drcontext, log_buffer, buf_base);
    return drx_buf_get_buffer_ptr(drcontext, log_buffer);
}

void
copy_log_entry_to_buf(void *drcontext, log_entry_t *entry)
{
     byte *buf_ptr = drx_buf_get_buffer_ptr(drcontext,
					    log_buffer);
     size_t buf_size = drx_buf_get_buffer_size(drcontext,
					       log_buffer);
     byte *buf_base = drx_buf_get_buffer_base(drcontext,
					      log_buffer);
     if ((buf_ptr + sizeof(log_entry_t)) >= (buf_base + buf_size)) {
	  /* is full, call this to empty */
	 buf_ptr = reset_log_buffer(drcontext, buf_base, buf_size);
     }
     /* if not safe to write, reset and force a memcpy */
     if (!dr_safe_write(buf_ptr, sizeof(log_entry_t), (void *)entry, NULL)) {
	 buf_ptr = reset_log_buffer(drcontext, buf_base, buf_size);
	 memcpy(buf_ptr, entry, sizeof(log_entry_t));
     }
     /* increment buf pointer to next slot */
     drx_buf_set_buffer_ptr(drcontext, log_buffer,
			    buf_ptr + sizeof(log_entry_t));

}


void
flush_log_buffer(void *drcontext, void *buf_base, size_t size)
{
     log_entry_t *trace_base = (log_entry_t *)(char *)buf_base;
     log_entry_t *trace_ptr = (log_entry_t *)((char *)buf_base + size);
     log_entry_t *log_ref;
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     /* write the log entries to disk */
     for (log_ref = trace_base; log_ref < trace_ptr; log_ref++) {
	  int kind = log_ref->kind;
	  /* sanity check log kind */
	  if ((0 <= kind)  && (kind < IS_KIND_MAX)) {
	       if (data->log_on || (log_all_calls & kind == IS_CALL)
		   || (kind == IS_FILE_WRITE && (prune_list || log_all_calls))) {
		    write_log(log_ref, data->logf);
	       }
	  } else if (kind == SET_LOG_ON) {
	       DR_ASSERT(!data->log_on);
	       data->log_on = true;
	       write_log(log_ref, data->logf);
	  } else if (kind == SET_LOG_OFF) {
	       DR_ASSERT(data->log_on);
	       data->log_on = false;
	       write_log(log_ref, data->logf);
	  } else {
	       dr_fprintf(STDERR, "Bad log type %x\n", log_ref->kind);
	       DR_ASSERT(false);
	  }
     }
     fflush(data->logf);
     /* (note: the log buffer pointer gets reset automatically) */
}

static void
logging_wrap(void *wrapcxt, bool enable_log, bool is_pre)
{
     /* wrapcxt may be null when unwinding from a longjmp */
     void *drcontext = wrapcxt ? drwrap_get_drcontext(wrapcxt): dr_get_current_drcontext();
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     bool was_enabled = data->logging_enabled;
     if (is_pre) {
	  if (enable_log) {
	       data->nested_log_on_count++;
	  } else {
	       data->nested_log_off_count++;
	  }
	  data->fn_filter_logging_enabled = enable_log;
     } else {
	  /* function is now returning. Should we reset the log? */
	  if (!enable_log) {
	       data->nested_log_on_count--;
	       if (data->nested_log_on_count == 0) {
		    data->fn_filter_logging_enabled = false;
	       }
	  } else {
	       data->nested_log_off_count--;
	       /* only reenable if we are returning to a fn with
		* logging enabled */
	       if (data->nested_log_off_count == 0 &&
		   data->nested_log_on_count > 0) {
		    data->fn_filter_logging_enabled = true;
	       }
	  }
     }
     DR_ASSERT(data->nested_log_on_count >= 0);
     DR_ASSERT(data->nested_log_off_count >= 0);
     if (file_offset_watchpoint) {
	  if (data->fn_filter_logging_enabled) {
	       /* only activate if watchpoint is active */
	       data->logging_enabled = data->file_offset_watchpoint_active;
	  }
     } else { /* fn filter is the only thing that determines if
	       * logging is enabled */
	  data->logging_enabled = data->fn_filter_logging_enabled;
     }
     if (was_enabled != data->logging_enabled) {
	  log_entry_t log;
	  app_pc func_pc = drwrap_get_func(wrapcxt);
	  /* TODO: may need to wrap next line in DR_TRY_EXCEPT */
	  app_pc ret_pc = drwrap_get_retaddr(wrapcxt);
	  size_t ins_len = 5;
	  app_pc caller = is_pre ? ret_pc - ins_len : 0;
	  if (data->logging_enabled) {
	       set_logging(drcontext, data->logging_enabled, func_pc,
			   &log, data);
	  }

	  /* sometimes the calls and returns don't make it into the log */
	  /* this is because the instrumentation hooks seem to run */
	  /* in the following order: */
	  /* bb_instrumentation (log CALL) -> wrap_pre (logging toggled) -> ... */
	  /*     -> bb_instrumentation (log RETURN) -> wrap_post (logging toggled) */
	  if (enable_log && calltrace && !log_all_calls) {
	      if (is_pre) {
		   /* TODO: can we determine whether caller pc is an
		    * inddirect call? */
		   /* size_t ins_len = 3 ? instr_is_call_indirect */
		  /* (note, the call instruction is 5 bytes , */
		  /*  long so <return address>-5 is the address */
		  /*  of the call instruction) */
		  /* We don't rely on previous call to populate_call_log */
		  /* to have correct pc stashed because function */
		  /* call may not have been instrumented by */
		  /* bb_instrumentation_event due to possible */
		  /* interference with drwrap_wrap instrumentation */
		   populate_call_log(caller, func_pc, CALL,
				     drcontext);
	      } else {
		  /* previously processed bb's entry will not be saved */
		  /* to the log, so generate a new log entry */
		  /* and tell populate_call_call to lookup */
		  /* the pc  stashed by the bb intrumentation's */
		  /* previous call to populate_call_log */
		   populate_call_log(caller, ret_pc, RETURN, drcontext);
	      }
	  }
	  if (enable_log && instrace && is_pre) {
	       log_entry_t l;
	       l.u.ins.pc = func_pc;
	       l.u.ins.rax = drwrap_get_arg(wrapcxt, 0);
	       l.u.ins.regs_saved = true;
	       l.kind = IS_INS;
	       copy_log_entry_to_buf(drcontext, &l);
	  }
	  if (!data->logging_enabled) {
	       set_logging(drcontext, data->logging_enabled, func_pc,
			   &log, data);
	  }

	  if(verbose) {
	       dr_printf("toggling log? log %s %s -- turning log %s (nested on: %d, nested off: %d), pc: %p\n",
			 enable_log == is_pre ? "enabling " : "disabling",
			 is_pre ? "fn call  " : "fn return",
			 data->logging_enabled ? "on " : "off",
			 data->nested_log_on_count,
			 data->nested_log_off_count,
			 func_pc);
	  }
     }
}

void
log_on_wrap_pre(void *wrapcxt, OUT void **user_data)
{
     logging_wrap(wrapcxt, true, true);
}
void
log_off_wrap_pre(void *wrapcxt, OUT void **user_data)
{
     logging_wrap(wrapcxt, false, true);
}

void
log_on_wrap_post(void *wrapcxt, void *user_data)
{
     logging_wrap(wrapcxt, false, false);
}

void
log_off_wrap_post(void *wrapcxt, void *user_data)
{
     logging_wrap(wrapcxt, true, false);
}


void
populate_call_log(app_pc instr_addr, app_pc target_addr, int kind, void *context)
{
     /* only retrieve context if not passed in as argument */
     dr_mcontext_t mc = {sizeof(mc), DR_MC_CONTROL | DR_MC_INTEGER};
     void *drcontext = context? context : dr_get_current_drcontext();
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     bool ok = dr_get_mcontext(drcontext, &mc);
     DR_ASSERT(ok);

     /* if instr_addr == 0, then this is being called */
     /* from drwrap and mc will not give us program counter */
     /* so we depend on previous call to this function */
     /* during bb instrumentation to have set data->bb_pc */
     if (instr_addr == 0) {
	 instr_addr = data->bb_pc;
     } else {
	 data->bb_pc = instr_addr;
     }

     log_entry_t l;
     l.u.call.kind = kind;
     l.u.call.target_addr = target_addr;
     l.u.call.pc = instr_addr;
     /* if (kind == RETURN) { */
     /* 	  /\* note that this doesn't always actually contain the value */
     /* 	   * for rax, particularly when this is called from */
     /* 	   * dr_insert_mbr_instrumentation *\/ */
     /* 	  l.u.call.stack_pointer = (app_pc) mc.rax; */
     /* } else { */
     l.u.call.stack_pointer = (app_pc) mc.rsp;
     /* } */
     l.kind = IS_CALL;
     copy_log_entry_to_buf(drcontext, &l);
}
