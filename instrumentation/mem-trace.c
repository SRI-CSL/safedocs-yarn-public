/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include "mem-trace.h"
#include "per-thread.h"
#include "prune.h"
#include "inputfd.h"
#include "syscall.h"
#include "logging.h"
#include "recording-utils.h"
#include "fn-wrap.h"
#include "mmap.h"
#include <fcntl.h>
#include <stddef.h> /* for offsetof */
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>
#include <libgen.h>
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drwrap.h"
#include "drx.h"
#include "utils.h"
#include "drsyms.h"
#include <unistd.h>

char *parser_input_path = NULL;
bool instrace = false;
bool calltrace = false;
bool malloctrace = false;
bool filewritetrace = false;
bool sockettrace = false;
bool foptrace = false;
bool main_entered = false;
bool verbose = false;
char *enable_logging_fns = NULL;
char *disable_logging_fns = NULL;

typedef struct {
     size_t sz;
} malloc_data_t;

int tls_idx;
client_id_t client_id;
static bool memtrace = false;
bool log_all_calls = false;
size_t file_offset_trigger = 0;
bool file_offset_watchpoint = false;
bool log_on_at_main = false;
/* bool log_on_at_entrypoint = false; */
static bool log_on_fns = false;
static bool log_off_fns = false;


static void module_load_event(void *drcontext, const module_data_t *mod,
			      bool loaded);
static void insert_save_pc_addr(void *drcontext, instrlist_t *ilist,
				instr_t *where, reg_id_t base,
				app_pc pc, drx_buf_t *buf, size_t offset);


static void
insert_save_ushort(void *drcontext, instrlist_t *ilist, instr_t *where,
		   reg_id_t base, size_t offset, ushort value)
{
     bool ok;
     ok = drx_buf_insert_buf_store(drcontext, log_buffer, ilist, where, base,
				   DR_REG_NULL,
				   OPND_CREATE_INT16(value), OPSZ_2, offset);
     DR_ASSERT(ok);
}

static void
insert_save_pc_addr(void *drcontext, instrlist_t *ilist, instr_t *where,
		    reg_id_t base, app_pc pc, drx_buf_t *buf, size_t offset)
{
     /* Insert instructions to load address of log (buf) to base register*/
     drx_buf_insert_load_buf_ptr(drcontext, buf, ilist, where, base);
     /* Insert instructions to save PC to *(base + offset) */
     drx_buf_insert_buf_store(drcontext, buf, ilist, where, base,
			      DR_REG_NULL, OPND_CREATE_INTPTR((ptr_int_t)pc),
			      OPSZ_PTR,
			      offset);
}


static bool
insert_save_register(void *drcontext, instrlist_t *ilist, instr_t *where,
		     reg_id_t base, reg_id_t save_reg,
		     drx_buf_t *buf, size_t offset, bool load_log_buffer)
{
     /* set base register to point to log buffer if needed*/
     if (load_log_buffer) {
	  drx_buf_insert_load_buf_ptr(drcontext, buf, ilist, where, base);
     }

     if (instr_uses_reg(where, save_reg) &&
	 drreg_get_app_value(drcontext, ilist, where, save_reg, save_reg)
	 != DRREG_SUCCESS) {
	  return false;
     }
     /* Insert instructions to save save_reg to *(base + offset) */
     drx_buf_insert_buf_store(drcontext, buf, ilist, where, base,
			      DR_REG_NULL,
			      opnd_create_reg(save_reg),
			      OPSZ_PTR,
			      offset);
     return true;
}

static void
insert_save_addr_and_value(void *drcontext, instrlist_t *ilist,
			   instr_t *where, opnd_t ref,
			   reg_id_t buf_ptr, reg_id_t ref_dst,
			   drx_buf_t *buf, size_t addr_offset,
			   size_t value_offset, ushort offset,
			   size_t memsz, size_t value_size,
			   bool addr_is_populated)
{
     bool ok;
     /* log_buffer entry in should already be in buf_ptr */
     /* we use buf_ptr reg as scratch to get addr of memory reference,
      * addr saved in ref_dst (we may not need to do this for mem
      * writes when offset == 0) */
     ok = drutil_insert_get_mem_addr(drcontext, ilist,
				     where, ref,
				     ref_dst, buf_ptr);
     DR_ASSERT(ok);
     if (offset > 0) {
	  /* if we need to fetch a non-zero offset from addr */
	  /* i.e., for instructions that fetch more than 1 quad */
	  if (!addr_is_populated) {
	       /* if addr isn't populated, then we increment by offset */
	       instrlist_meta_preinsert(ilist, where,
		       XINST_CREATE_add(drcontext,
					opnd_create_reg(ref_dst), // dst
					OPND_CREATE_INT8(offset)));
	  } else {
	       /* if addr is populated, then its value equals the */
	       /* offset of the previous offset that was fetched so we */
	       /* only need to increment it by the number of bytes we */
	       /* copy per value fetch (value_size) */
	       instrlist_meta_preinsert(ilist, where,
		       XINST_CREATE_add(drcontext,
					opnd_create_reg(ref_dst), // dst
					OPND_CREATE_INT8(value_size)));
	  }
     }
     /* ref_dst now holds address of memory reference */


     /* insert instruction to store OPSZ_PTR bytes the (contents of */
     /* ref_dst) at addr_offset bytes from buf_ptr, effectively */
     /* setting the addr field of the current log entry */
     ok = drx_buf_insert_buf_store(drcontext, buf, ilist, where,
				   buf_ptr, DR_REG_NULL,
				   opnd_create_reg(ref_dst),
				   OPSZ_PTR, addr_offset);

     DR_ASSERT(ok);


     /* set buf_pointer to be where value needs to be written */
     drx_buf_insert_update_buf_ptr(drcontext, log_buffer, ilist, where,
				   buf_ptr, DR_REG_NULL, value_offset);

     drx_buf_insert_buf_memcpy(drcontext, log_buffer, ilist, where,
			       buf_ptr, ref_dst, memsz);
     /* now buf_pointer points to address after copied value */


     /* update pointer to points to next field */
     if (value_size - memsz > 0) {
	  drx_buf_insert_update_buf_ptr(drcontext, log_buffer, ilist, where,
					buf_ptr, DR_REG_NULL,
					value_size - memsz);
     }
}


/* insert inline code to save address of mem write*/
static bool
instrument_pre_mem_write(void *drcontext, instrlist_t *ilist,
			 instr_t *where, opnd_t ref, write_info_t *regs)

{
     bool ok;
     opnd_t opnd1;
     size_t log_offset;
     ushort memsz;
     ushort writtensz, remaining;
     reg_id_t reg_tmp;
     if (instr_is_call(where) || instr_is_cti(where) || instr_is_return(where)) {
	  /* don't bother saving writes that occur in control transfer
	   * instructions */
	  regs->addr_reg = DR_REG_NULL;
	  return false;
     }
     memsz = drutil_opnd_mem_size_in_bytes(ref, where);
     instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
     if (drreg_reserve_register(drcontext, ilist, where, NULL,
				&(regs->addr_reg)) != DRREG_SUCCESS ||
	 drreg_reserve_register(drcontext, ilist, where, NULL,
				&reg_tmp) != DRREG_SUCCESS) {
	  DR_ASSERT(false); /* cannot recover */
	  regs->addr_reg = DR_REG_NULL;
	  return false;
     }
     /* make sure we save and restore the register being used to track
      * memory write values, if already in use */
     if (opnd_uses_reg(ref, regs->addr_reg) &&
	 drreg_get_app_value(drcontext, ilist, where, regs->addr_reg,
			     regs->addr_reg)
	 != DRREG_SUCCESS) {
	  DR_ASSERT(false);
	  regs->addr_reg = DR_REG_NULL;
	  return false;
     }

     /* use pc_reg as scratch to get addr */
     ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref,
				     regs->addr_reg,
				     reg_tmp);

     /* Restore scratch registers */
     if (!ok || drreg_unreserve_register(drcontext, ilist, where, reg_tmp)
	 != DRREG_SUCCESS) {
	  DR_ASSERT(false);
	  regs->addr_reg = DR_REG_NULL;
	  return false;
     }
     return true;
}

/* insert inline code to add a memory reference info entry into the buffer */
static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
	       instr_t *write_instr, opnd_t ref, write_info_t *regs)
{
     bool ok;
     /* We need two scratch registers */
     reg_id_t buf_ptr, reg_tmp;
     opnd_t opnd1;
     size_t log_offset, value_size = sizeof(unsigned long long);
     ushort writtensz, remaining, mem_type;
     ushort memsz;
     app_pc pc;

     if (drreg_reserve_register(drcontext, ilist, where, NULL, &buf_ptr) !=
	 DRREG_SUCCESS ||
	 drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
	 DRREG_SUCCESS) {

	  DR_ASSERT(false); /* cannot recover */
	  return;
     }

     if (write_instr != NULL) {
	  /* if instrumenting a write, these meta instructions are
	   * added after the write instruction -- i.e., `where` is the
	   * instruction that follows the write, so set auto predicate
	   * to match write instruction and get info about write
	   * instruction */
	  DR_ASSERT(regs->addr_reg != DR_REG_NULL);
	  DR_ASSERT(!opnd_uses_reg(ref, regs->addr_reg));
	  instrlist_set_auto_predicate(ilist, instr_get_predicate(write_instr));
	  memsz = drutil_opnd_mem_size_in_bytes(ref, write_instr);
	  pc = instr_get_app_pc(write_instr);
	  mem_type = REF_TYPE_WRITE;
     } else {
	  /* if instrumenting a read, gather information on read */
	  instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
	  memsz = drutil_opnd_mem_size_in_bytes(ref, where);
	  pc = instr_get_app_pc(where);
	  mem_type = REF_TYPE_READ;
     }

     /* make sure we save and restore the register being used to track
      * memory write values, if in use and used by current instruction */
     if (regs->addr_reg != DR_REG_NULL &&
	 opnd_uses_reg(ref, regs->addr_reg) &&
	 drreg_get_app_value(drcontext, ilist, where, regs->addr_reg,
			     regs->addr_reg)
	 != DRREG_SUCCESS) {
	  DR_ASSERT(false);
	  return;
     }

     for (ushort offset = 0; offset < memsz;
	  offset = offset + value_size) {
	  /* we breakup larger mem reads into multiple log entries, so */
	  /* calculate the number of bytes we read into the log per */
	  /* log entry */
	  remaining = memsz - offset;
	  writtensz = remaining > value_size ? value_size : remaining;

	  /* save instruction pc */
	  insert_save_pc_addr(drcontext, ilist, where, buf_ptr, pc,
			      log_buffer, offsetof(mem_ref_t, pc));
	  /* now buf_ptr is set to beginning of log entry being populated */

	  /* save log type */
	  ok = drx_buf_insert_buf_store(drcontext, log_buffer, ilist, where,
					buf_ptr, DR_REG_NULL,
					OPND_CREATE_INT32(IS_MEM_REF),
					OPSZ_4,
					offsetof(log_entry_t, kind));
	  DR_ASSERT(ok);

	  /* save whether this was a mem read or write operation */
	  insert_save_ushort(drcontext, ilist, where, buf_ptr,
			     offsetof(mem_ref_t, type), mem_type);

	  /* save_addr should be called first as buf_ptr or reg_tmp */
	  /* maybe used in ref */
	  if (write_instr != NULL) {
	       insert_save_addr_and_value(drcontext, ilist,
					  where, ref,
					  buf_ptr,
					  regs->addr_reg,
					  log_buffer,
					  offsetof(mem_ref_t, addr),
					  offsetof(mem_ref_t, value),
					  offset, writtensz,
					  value_size, true);
	  } else {
	       insert_save_addr_and_value(drcontext, ilist,
					  where, ref,
					  buf_ptr,
					  reg_tmp,
					  log_buffer,
					  offsetof(mem_ref_t, addr),
					  offsetof(mem_ref_t, value),
					  offset, writtensz,
					  value_size, false);
	  }

	  /* now buf_pointer points to address after copied value, so */
	  /* adjust future buf_ptr store offsets so they are relative to this */
	  /* offset and not the beginning of the log entry */
	  log_offset = offsetof(mem_ref_t, value) + value_size;

	  /* save number of bytes read and stored in log entry */
	  insert_save_ushort(drcontext, ilist, where, buf_ptr,
			     offsetof(mem_ref_t, size) - log_offset,
			     writtensz);


	  /* update the log_buffer pointer to point to next entry */
	  drx_buf_insert_update_buf_ptr(drcontext, log_buffer, ilist, where,
					buf_ptr, DR_REG_NULL,
					sizeof(log_entry_t) - log_offset);
     }

     /* Restore scratch registers */
     if (drreg_unreserve_register(drcontext, ilist, where, buf_ptr)
	 != DRREG_SUCCESS ||
	 drreg_unreserve_register(drcontext, ilist, where, reg_tmp)
	 != DRREG_SUCCESS)
	  DR_ASSERT(false);
     if (write_instr != NULL) {
	  instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
	  if ( drreg_unreserve_register(drcontext, ilist, where, regs->addr_reg)
	       != DRREG_SUCCESS) {
	       DR_ASSERT(false);
	  }
     }

}

static void
handle_post_mem_write(void *drcontext, instrlist_t *ilist, instr_t *where,
		      write_info_t *regs) {
    int i;
    instr_t *prev_instr = instr_get_prev_app(where);
    /* XXX: We assume that no write instruction has multiple distinct memory destinations.
     * This way we are able to persist a single register across an app instruction. Note
     * there are instructions which currently do break this assumption, but we punt on
     * this.
     */
    for (i = 0; i < instr_num_dsts(prev_instr); ++i) {
        if (opnd_is_memory_reference(instr_get_dst(prev_instr, i))) {
            if (regs->addr_reg == DR_REG_NULL) {
                DR_ASSERT_MSG(false,
			      "Found inst with multiple memory destinations");
                break;
            }
	    instrument_mem(drcontext, ilist, where, prev_instr,
			   instr_get_dst(prev_instr, i), regs);

	    regs->addr_reg = DR_REG_NULL;
        }
    }
}


static void
save_target_call(app_pc instr_addr, app_pc target_addr)
{
     populate_call_log(instr_addr, target_addr, CALL, NULL);
}


static void
save_target_indirect(app_pc instr_addr, app_pc target_addr)
{
     populate_call_log(instr_addr, target_addr, INDIRECT, NULL);
}


static void
save_target_indjmp(app_pc instr_addr, app_pc target_addr)
{
     populate_call_log(instr_addr, target_addr, INDIRECT_JMP, NULL);
}


static void
save_target_return(app_pc instr_addr, app_pc target_addr)
{
     populate_call_log(instr_addr, target_addr, RETURN, NULL);

}

static void
instrument_ins_trace(void *drcontext, instrlist_t *ilist,
		     instr_t *where, write_info_t *regs)
{
     reg_id_t reg_ptr, reg_tmp;
     bool ok;
     per_thread_mem_t *data;
     /* don't predicate this because fetch always occurs */
     instrlist_set_auto_predicate(ilist, DR_PRED_NONE);
     data = (per_thread_mem_t *) drmgr_get_tls_field(drcontext, tls_idx);
     if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
	 DRREG_SUCCESS ||
	 drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
	 DRREG_SUCCESS) {

	  DR_ASSERT(false); /* cannot recover */
	  return;
     }
     /* make sure we save and restore the register being used to track
      * memory write values, if in use */
     if (regs->addr_reg != DR_REG_NULL &&
	 instr_uses_reg(where, regs->addr_reg) &&
	 drreg_get_app_value(drcontext, ilist, where, regs->addr_reg,
			     regs->addr_reg)
	 != DRREG_SUCCESS) {
	  DR_ASSERT(false);
	  return;
     }

     /* save pc addr in current log entry */
     insert_save_pc_addr(drcontext, ilist, where, reg_ptr,
			 instr_get_app_pc(where),
			 log_buffer,
			 offsetof(ins_ref_t, pc));

     /* save rax value in current log entry */
     ok = insert_save_register(drcontext, ilist, where, reg_ptr,
			       DR_REG_RAX, log_buffer,
			       offsetof(ins_ref_t, rax), false);
     /* dynamorio seems to always fail in drreg_get_app_value for RDI */
     /* at function entry points -- we were hoping to get the value of */
     /* RDI when a function is called so we can stash the function's argument */
     /* -- so for now we will not save the value of rdx */
     /* if (ok) { */
     /* 	 /\* save rdi value in current log entry *\/ */
     /* 	 ok = insert_save_register(drcontext, ilist, where, reg_ptr, */
     /* 				   DR_REG_RDI, log_buffer, */
     /* 				   offsetof(ins_ref_t, rdi), false); */
     /* } */
     insert_save_ushort(drcontext, ilist, where, reg_ptr,
			offsetof(ins_ref_t, regs_saved), (ushort) ok);


     /* save log type (IS_INS) in current log entry */
     ok = drx_buf_insert_buf_store(drcontext, log_buffer, ilist, where,
				   reg_ptr, DR_REG_NULL,
				   OPND_CREATE_INT32(IS_INS), OPSZ_4,
				   offsetof(log_entry_t, kind));
     DR_ASSERT(ok);


     drx_buf_insert_update_buf_ptr(drcontext, log_buffer, ilist, where, reg_ptr,
				  DR_REG_NULL, sizeof(log_entry_t));
     /* Restore scratch registers */
     if (drreg_unreserve_register(drcontext, ilist,
				  where, reg_ptr) != DRREG_SUCCESS ||
	 drreg_unreserve_register(drcontext, ilist,
				  where, reg_tmp) != DRREG_SUCCESS)
	  DR_ASSERT(false);
     /* reset predicate */
     instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
}


static dr_emit_flags_t
event_app_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                   bool translating, void **user_data)
{
    per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);

    *user_data = (void *)&data->write_regs;
    /* If we have an outstanding write, that means we did not
     * correctly handle a case where there was a write but no
     * fall-through NOP or terminating instruction in the previous
     * basic block.
     */
    DR_ASSERT(data->write_regs.addr_reg == DR_REG_NULL);
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
		      instr_t *instr, bool for_trace, bool translating,
		      void *user_data)
{
     int i;
     write_info_t *write_regs = (write_info_t *) user_data;
     per_thread_mem_t *data;
     bool do_instrument;
     if (memtrace & write_regs->addr_reg != DR_REG_NULL) {

	  handle_post_mem_write(drcontext, bb, instr, write_regs);
	  //drreg_unreserve_register(drcontext, bb, instr, write_regs->addr_reg);
	  //write_regs->addr_reg = DR_REG_NULL;
     }
     if (!instr_is_app(instr))
	  return DR_EMIT_DEFAULT;
     do_instrument = (prune_list == NULL) || addr_in_prune_list(instr_get_app_pc(instr));
     if (instrace && do_instrument && drmgr_is_first_instr(drcontext, instr)) {
	  instrument_ins_trace(drcontext, bb, instr, write_regs);
     }
     /* insert code to add an entry for each memory reference opnd */
     /* skip copying prefetched addresses as the application may not */
     /* be allowed to actually read the address, so forcing a read of it */
     /* can cause a segfault that the application would otherwise not see */
     if (memtrace && do_instrument && (instr_reads_memory(instr) || instr_writes_memory(instr))
	 && (!instr_is_prefetch(instr))) {
	  for (i = 0; i < instr_num_srcs(instr); i++) {
	       if (opnd_is_memory_reference(instr_get_src(instr, i))) {
		   instrument_mem(drcontext, bb, instr, NULL,
				  instr_get_src(instr, i),
				  write_regs);
	       }
	  }

	  for (i = 0; i < instr_num_dsts(instr); i++) {
	       if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
		    if (write_regs->addr_reg == DR_REG_NULL) {
			 instrument_pre_mem_write(drcontext, bb, instr,
						  instr_get_dst(instr, i),
						  write_regs);
		    }else{
			 DR_ASSERT(false);
		    }

	       }
	  }

     }
     /* instrument calls and returns -- ignore far calls/rets */
     if (calltrace) {
	  if (instr_is_call_direct(instr)) {
	      dr_insert_call_instrumentation(drcontext, bb, instr,
					     (app_pc)save_target_call);
	  } else if (instr_is_call_indirect(instr)) {
	       dr_insert_mbr_instrumentation(drcontext, bb, instr,
					     (app_pc)save_target_indirect,
					     SPILL_SLOT_1);
	  } else if (instr_is_return(instr)) {
	       /* this actually needs to save return addr on top of stack */
	       dr_insert_mbr_instrumentation(drcontext, bb, instr,
					     (app_pc)save_target_return,
					     SPILL_SLOT_1);
	  } else if (instr_get_opcode(instr) == OP_jmp_ind) {
	       dr_insert_mbr_instrumentation(drcontext, bb, instr,
					     (app_pc)save_target_indjmp,
					     SPILL_SLOT_1);
	  }
     }
     return DR_EMIT_DEFAULT;
}

/* We transform string loops into regular loops so we can more easily
 * monitor every memory reference they make.
 */
static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
		 bool translating)
{
     if (!drutil_expand_rep_string(drcontext, bb)) {
	  DR_ASSERT(false);
	  /* in release build, carry on: we'll just miss per-iter refs */
     }
     drx_tail_pad_block(drcontext, bb);
     return DR_EMIT_DEFAULT;
}

static dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *info)
{
    log_entry_t log;
    per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
    log.kind = IS_SIG;
    log.u.sig.pc = decode_next_pc(drcontext, info->mcontext->pc);
    log.u.sig.sig = info->sig;
    copy_log_entry_to_buf(drcontext, &log);
    return DR_SIGNAL_DELIVER;
}

static void
event_thread_init(void *drcontext)
{
     log_entry_t log;
     dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL /*only need pc*/ };
     per_thread_mem_t *data = dr_thread_alloc(drcontext,
					      sizeof(per_thread_mem_t));

     bool ok = dr_get_mcontext(drcontext, &mc);
     // This will fail for first created thread
     // DR_ASSERT(ok);
     data->syscall_input_just_opened = false;
     /* store it in the slot provided in the drcontext */
     DR_ASSERT(data != NULL);
     drmgr_set_tls_field(drcontext, tls_idx, data);

     /* We're going to dump our data to a per-thread file.
      * On Windows we need an absolute path so we place it in
      * the same directory as our library. We could also pass
      * in a path as a client argument.
      */
     data->log =
	  log_file_open(client_id, drcontext,
			logdir,
			"memcalltrace",
#ifndef WINDOWS
			DR_FILE_CLOSE_ON_FORK |
#endif
			DR_FILE_ALLOW_LARGE);
     data->logf = log_stream_from_file(data->log);
     if (filewritetrace) {
	 data->write_log =
	     log_file_open(client_id, drcontext,
			   logdir,
			   "write",
#ifndef WINDOWS
			   DR_FILE_CLOSE_ON_FORK |
#endif
			   DR_FILE_ALLOW_LARGE);
	 data->write_logf = log_stream_from_file(data->write_log);
	 data->write_idx = 0;
     }
     data->log_on = !main_entered;
     data->logging_enabled = main_entered;
     data->fn_filter_logging_enabled = main_entered;
     data->file_offset_watchpoint_active = false;
     data->nested_log_on_count = 0;
     data->nested_log_off_count = 0;
     data->write_regs.addr_reg = DR_REG_NULL;
     set_logging(drcontext, data->logging_enabled, mc.pc, &log, data);
     if (verbose) {
	  dr_printf("event thread init\n");
     }
     /* if (log_on_at_entrypoint) { */
     /* 	  log_on_wrap_pre(NULL, NULL); */
     /* 	  save_mmap(dr_get_current_drcontext()); */
     /* } */
}

static void
event_thread_exit(void *drcontext)
{
     per_thread_mem_t *data;
     void *ptr, *base;
     data = drmgr_get_tls_field(drcontext, tls_idx);
     /* if (log_on_at_entrypoint) { */
     /* 	  data->nested_log_off_count = 1; */
     /* 	  log_off_wrap_post(NULL, NULL); */
     /* } */
     data->logging_enabled = false;
     data->nested_log_on_count = 0;
     data->nested_log_off_count = 0;
     log_stream_close(data->logf); /* closes fd too */
     if (filewritetrace) {
	      log_stream_close(data->write_logf);
     }
     dr_thread_free(drcontext, data, sizeof(per_thread_mem_t));
}

static void
event_exit(void)
{
     void *drcontext = dr_get_current_drcontext();
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     if (verbose) {
	  dr_printf("event exit\n");
     }

     if (!drmgr_unregister_tls_field(tls_idx) ||
	 !drmgr_register_signal_event(event_signal) ||
	 !drmgr_unregister_module_load_event(module_load_event) ||
	 !drmgr_unregister_thread_init_event(event_thread_init) ||
	 !drmgr_unregister_thread_exit_event(event_thread_exit) ||
	 !drmgr_unregister_bb_app2app_event(event_bb_app2app) ||
	 /* this fails for some reason */
	 // !drmgr_unregister_bb_instrumentation_event(event_app_analysis) ||
	 !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
	 drreg_exit() != DRREG_SUCCESS)
	  DR_ASSERT(false);
     if (foptrace || sockettrace) {
	  if(!dr_unregister_filter_syscall_event(syscall_filter) ||
	     !drmgr_unregister_pre_syscall_event(pre_syscall) ||
	     !drmgr_unregister_post_syscall_event(post_syscall))
	       DR_ASSERT(false);
     }
     if (prune_list != NULL) {
	  dr_global_free(prune_list, sizeof(app_pc) * prune_list_alloc_size);
     }
     if (prune_list_mutex != NULL) {
	  dr_mutex_destroy(prune_list_mutex);
     }
     dr_mutex_destroy(mmap_mutex);
     dr_mutex_destroy(input_fd_mutex);
     dr_mutex_destroy(fn_parser_mutex);
     drx_buf_free(log_buffer);
     drx_exit();
     drutil_exit();
     drsym_exit();
     drmgr_exit();
}


static void
copy_wrap_log_entry_to_buf(log_entry_t *entry, void *wrapcxt)
{
     void *drcontext = drwrap_get_drcontext(wrapcxt);
     copy_log_entry_to_buf(drcontext, entry);
}

static void
free_wrap_pre(void *wrapcxt, OUT void **user_data)
{
     void *drcontext = drwrap_get_drcontext(wrapcxt);
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     log_entry_t head;
     head.kind = IS_MALLOC;
     head.u.malloc.addr = drwrap_get_arg(wrapcxt, 0);
     head.u.malloc.pc = drwrap_get_func(wrapcxt);
     head.u.malloc.num_bytes = 0;
     head.u.malloc.kind = MALLOC_FREE;
     copy_wrap_log_entry_to_buf(&head, wrapcxt);
}

static void
_alloc_wrap_pre(void *wrapcxt, OUT void **user_data, size_t size)
{
     /* save malloc's first argument so we know number of bytes malloc'd */
     void *drcontext = drwrap_get_drcontext(wrapcxt);
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     malloc_data_t *m;
     m = dr_global_alloc(sizeof(malloc_data_t));
     m->sz = size;
     *user_data = (void *)m;

}

static void
_alloc_wrap_post(void *wrapcxt, void *user_data, int kind)
{
    /* wrapcxt may be null when unwinding from a longjmp, we do not
       know how to recover from this yet, luckily this is rare */
     DR_ASSERT(wrapcxt != NULL);
     void *drcontext = drwrap_get_drcontext(wrapcxt);
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     malloc_data_t *m = (malloc_data_t *) user_data;

     void *ret = drwrap_get_retval(wrapcxt);
     log_entry_t head;

     head.u.malloc.addr = ret;
     head.u.malloc.pc = drwrap_get_func(wrapcxt);
     head.u.malloc.num_bytes = m->sz;
     head.u.malloc.kind = kind;
     head.kind = IS_MALLOC;
     copy_wrap_log_entry_to_buf(&head, wrapcxt);
     dr_global_free(user_data, sizeof(malloc_data_t));
}

static void
malloc_wrap_pre(void *wrapcxt, void **user_data)
{
    _alloc_wrap_pre(wrapcxt, user_data,
		    (size_t) drwrap_get_arg(wrapcxt, 0));
}
static void
malloc_wrap_post(void *wrapcxt, void *user_data)
{
    _alloc_wrap_post(wrapcxt, user_data, MALLOC_MALLOC);
}


static void
calloc_wrap_pre(void *wrapcxt, void **user_data)
{
    _alloc_wrap_pre(wrapcxt, user_data,
		    (size_t) drwrap_get_arg(wrapcxt, 0) *
		    (size_t) drwrap_get_arg(wrapcxt, 1));
}

static void
calloc_wrap_post(void *wrapcxt, void *user_data)
{
    _alloc_wrap_post(wrapcxt, user_data, MALLOC_CALLOC);
}
static void
realloc_wrap_pre(void *wrapcxt, void **user_data)
{
     void *drcontext = drwrap_get_drcontext(wrapcxt);
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
    log_entry_t head;
    head.kind = IS_MALLOC;
    head.u.malloc.addr = drwrap_get_arg(wrapcxt, 0);
    head.u.malloc.pc = drwrap_get_func(wrapcxt);
    head.u.malloc.num_bytes = 0;
    head.u.malloc.kind = MALLOC_REALLOC_FREE;
    copy_wrap_log_entry_to_buf(&head, wrapcxt);

    _alloc_wrap_pre(wrapcxt, user_data,
		    (size_t) drwrap_get_arg(wrapcxt, 1));

}
static void
realloc_wrap_post(void *wrapcxt, void **user_data)
{
    _alloc_wrap_post(wrapcxt, user_data, MALLOC_REALLOC);
}
static void
reallocarray_wrap_pre(void *wrapcxt, void **user_data)
{
     void *drcontext = drwrap_get_drcontext(wrapcxt);
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     log_entry_t head;
     head.kind = IS_MALLOC;
     head.u.malloc.addr = drwrap_get_arg(wrapcxt, 0);
     head.u.malloc.pc = drwrap_get_func(wrapcxt);
     head.u.malloc.num_bytes = 0;
     head.u.malloc.kind = MALLOC_REALLOCARRAY_FREE;
     copy_wrap_log_entry_to_buf(&head, wrapcxt);

    _alloc_wrap_pre(wrapcxt, user_data,
		    (size_t) drwrap_get_arg(wrapcxt, 1) *
		    (size_t) drwrap_get_arg(wrapcxt, 2));
}
static void
reallocarray_wrap_post(void *wrapcxt, void **user_data)
{
    _alloc_wrap_post(wrapcxt, user_data, MALLOC_REALLOCARRAY);
}

static void
dlopen_wrap_pre(void *wrapcxt, OUT void **user_data)
{
     if (verbose) {
	  void *drcontext = drwrap_get_drcontext(wrapcxt);
	  per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	  data->dlopen_path = (char *) drwrap_get_arg(wrapcxt, 0);
     }
}

static void
dlopen_wrap_post(void *wrapcxt, void *user_data)
{
     /* wrapcxt may be null when unwinding from a longjmp */
     void *drcontext = wrapcxt ? drwrap_get_drcontext(wrapcxt): dr_get_current_drcontext();
     if (verbose) {
	  per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	  dr_printf("dlopen called for %s\n", data->dlopen_path);
	  data->dlopen_path = NULL;
     }
     save_mmap(drcontext);
}
static void
dlclose_wrap_pre(void *wrapcxt, void *user_data)
{
     if (verbose) {
	  dr_printf("skipping call to dlclose()\n");
     }
     /* "return" 0 to simulate a sucessful call */
     drwrap_skip_call(wrapcxt, (void *) 0, 0);
}

static void
main_wrap_pre(void *wrapcxt, OUT void **user_data)
{
     int mmap_filed, out_filed;
     struct stat mmap_stat;
     int res;
     off_t fsize;
     size_t bytes, len;
     log_entry_t log;
     dr_printf("main entered\n");
     main_entered = true;
     if (log_on_at_main){
	  dr_printf("enabling logging at main\n");
	  log_on_wrap_pre(wrapcxt, user_data);
	  /* log entry for call to main will be inserted by above call
	   * to log_on_wrap_pre */
     }
     /* main() is being called */
     /* save copy of memory map when main is first callsed */
     save_mmap(drwrap_get_drcontext(wrapcxt));
}

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
     app_pc towrap;
     if (!main_entered) {
	  void *post_fn = NULL;
	  if (log_on_at_main) {
	       post_fn = log_on_wrap_post;
	  }
	  do_wrap("main", main_wrap_pre, post_fn, mod);
     }
     do_wrap("dlopen", dlopen_wrap_pre, dlopen_wrap_post, mod);
     do_wrap("dlclose", dlclose_wrap_pre, NULL, mod);
     if (log_on_fns && enable_logging_fns) {
	  wrap_logging_fns(enable_logging_fns, true, mod);
     }
     if (log_off_fns && disable_logging_fns) {
	  wrap_logging_fns(disable_logging_fns, false, mod);
     }

     if (malloctrace) {
	  do_wrap("malloc", malloc_wrap_pre, malloc_wrap_post, mod);
	  do_wrap("calloc", calloc_wrap_pre, calloc_wrap_post, mod);
	  do_wrap("realloc", realloc_wrap_pre, realloc_wrap_post, mod);
	  do_wrap("reallocarray", reallocarray_wrap_pre, reallocarray_wrap_post,
		  mod);
	  do_wrap("free", free_wrap_pre, NULL, mod);
     }
     if (prune_list_libs != NULL) {
	  update_prune_list(mod, NULL, NULL);
     }
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
     int opt;
     int digit_optind = 0;
     size_t div, len, tok_len, sz;
     char *token, *last;
     const char sep[2] = ",";
     char *list_size;
     char *list_contents;
     char *file_offset_str;
     app_pc last_addr = 0;
     drmgr_priority_t priority = { sizeof(priority), "memtrace", NULL, NULL, 0};

     /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
     drreg_options_t ops = { sizeof(ops), 3, false };
     dr_set_client_name("Memory and calltraces 'memcalltrace'",
			"http://dynamorio.org/issues");

     if (!drmgr_init() || drreg_init(&ops)  != DRREG_SUCCESS ||
	 !drutil_init() || !drwrap_init() || !drx_init() ||
	 drsym_init(0) != DRSYM_SUCCESS)
	  DR_ASSERT(false);

     /* optarg does not handle spaces in option arguments properly, instead */
     /* returning the rest of argv, which is frustrating. */
     /* while ((opt = getopt(argc, (char **)argv, "camivIoeDdsApwE")) != -1) { */
     while ((opt = getopt(argc, (char **)argv, "camivIoeDdsApw")) != -1) {
	  switch (opt) {
	  case 'c':
	       calltrace = true;
	       break;
	  case 'A':
	       log_all_calls = true;
	       break;
	  case 'i':
	       instrace = true;
	       break;
	  case 'a':
	       malloctrace = true;
	       break;
	  case 'w':
	       filewritetrace = true;
	       break;
	  case 'm':
	       memtrace = true;
	       break;
	  case 'p':
	       DR_ASSERT(prune_list_libs == NULL);
	       prune_list_libs = getenv("NOMAD_META_MR_MT_PRUNE_LIST_LIBS");
	       DR_ASSERT(prune_list_libs != NULL);
	       prune_list_contents = getenv("NOMAD_META_MR_MT_PRUNE_LIST");
	       DR_ASSERT(prune_list_contents != NULL);
	       libc_name = getenv("NOMAD_META_MR_MT_LIBC_NAME");
	       prune_list_mutex = dr_mutex_create();
	       break;
	  case 's':
	       sockettrace = true;
	  case 'd':
	       logdir = getenv("NOMAD_META_MR_MT_LOG_DIR");
	       break;
	  case 'I':
	       /* because option argument parsing is screwed up in dynamorio */
	       foptrace = true;
	       DR_ASSERT(parser_input_path == NULL);
	       parser_input_path = getenv("NOMAD_META_MR_MT_DOC_PATH");
	       DR_ASSERT(parser_input_path != NULL);
	       dr_printf("parser input: %s (%ld)\n", parser_input_path,
			 strlen(parser_input_path));
	       break;
	  case 'o':
	       file_offset_watchpoint = true;
	       file_offset_str = getenv("NOMAD_META_MR_MT_DOC_OFFSET_ERR");
	       DR_ASSERT(file_offset_str != NULL);
	       file_offset_trigger = strtoull(file_offset_str, NULL, 0);
	       dr_printf("input offset trigger: %ld\n", file_offset_trigger);
	       break;
	  case 'e':
	       DR_ASSERT(enable_logging_fns == NULL);
	       enable_logging_fns = getenv("NOMAD_META_MR_MT_ENABLE_LOG");
	       DR_ASSERT(enable_logging_fns != NULL);
	       /* check if "main" is in list */
	       /* log_on_at_entrypoint = false; */
	       len = strlen(enable_logging_fns);
	       last = &enable_logging_fns[len];
	       token = strtok(enable_logging_fns, sep);
	       if (token) {
		   log_on_fns = true;
	       }
	       while (token) {
		    if (strncmp(token, "main", 5) == 0) {
			 log_on_at_main = true;
		    }
		    /* strtok replaces sep with 0, restore separator */
		    /* so we can use strtok again against this string */
		    if(&(token[strlen(token)]) < last) {
			 token[strlen(token)] = ',';
		    }
		    token = strtok(NULL, sep);
	       }
	       dr_printf("Logging enabling fns specified: %s\n",
			 enable_logging_fns);
	       break;
	  case 'D':
	       DR_ASSERT(disable_logging_fns == NULL);
	       disable_logging_fns = getenv("NOMAD_META_MR_MT_DISABLE_LOG");
	       dr_printf("Logging disabling fns specified: %s\n",
			 disable_logging_fns);
	       DR_ASSERT(disable_logging_fns != NULL);
	       log_off_fns = true;
	       break;
	  /* case 'E': */
	  /*      log_on_at_entrypoint = true; */
	  /*      log_on_at_main = true; */
	  /*      log_on_fns = false; */
	  /*      enable_logging_fns = NULL; */
	  /*      disable_logging_fns = NULL; */
	  /*      log_off_fns = false; */
	  /*      break; */
	  case 'v':
	      verbose = true;
	      break;
	  default:
	       dr_fprintf(STDERR, "unknown option %c (%d)\n", opt, opt);
	       break;
	  }
     }
     if (NULL == enable_logging_fns) {
	  log_on_at_main = true;
     }

     if (verbose) {
	  dr_printf("sizeof(mem_ref_t) = %lu\n", sizeof(mem_ref_t));
	  dr_printf("sizeof(reg_ref_t) = %lu\n", sizeof(reg_ref_t));
	  dr_printf("sizeof(call_ref_t) = %lu\n", sizeof(call_ref_t));
	  dr_printf("sizeof(malloc_ref_t) = %lu\n", sizeof(malloc_ref_t));
	  dr_printf("sizeof(ins_ref_t) = %lu\n", sizeof(ins_ref_t));
	  dr_printf("sizeof(mmap_op_t) = %lu\n", sizeof(mmap_op_t));
	  dr_printf("sizeof(file_op_t) = %lu\n", sizeof(file_op_t));
	  dr_printf("sizeof(sig_ref_t) = %lu\n", sizeof(sig_ref_t));
	  dr_printf("sizeof(sock_recv_t) = %lu\n", sizeof(sock_recv_t));
	  dr_printf("sizeof(log_entry_t) = %lu\n", sizeof(log_entry_t));
     }
     sz = sizeof(mem_ref_t);
     DR_ASSERT(sz == sizeof(reg_ref_t) && sz == sizeof(call_ref_t) &&
	       sz == sizeof(malloc_ref_t) && sz == sizeof(ins_ref_t) &&
	       sz == sizeof(mmap_op_t) && sz == sizeof(file_op_t) &&
	       sz == sizeof(sig_ref_t) && sz == sizeof(sock_recv_t));
     for (int i = 0; i < MAX_INPUT_FDS; i++) {
	 input_fd[i] = 0;
     }
     input_opened = false;


     /* register events */
     dr_register_exit_event(event_exit);
     if (!drmgr_register_thread_init_event(event_thread_init) ||
	 !drmgr_register_thread_exit_event(event_thread_exit) ||
	 !drmgr_register_signal_event(event_signal) ||
	 !drmgr_register_bb_app2app_event(event_bb_app2app, &priority) ||
	 !drmgr_register_bb_instrumentation_event(event_app_analysis,
						  event_app_instruction,
						  &priority) ||
	 !drmgr_register_module_load_event(module_load_event))
	  DR_ASSERT(false);
     if (foptrace || sockettrace) {
	  dr_register_filter_syscall_event(syscall_filter);
	  if(
	       !drmgr_register_pre_syscall_event(pre_syscall) ||
	       !drmgr_register_post_syscall_event(post_syscall))
	       DR_ASSERT(false);
     }

     client_id = id;
     tls_idx = drmgr_register_tls_field();
     DR_ASSERT(tls_idx > -1);
     if (prune_list != NULL) {
	  prune_list_mutex = dr_mutex_create();
     }

     mmap_mutex = dr_mutex_create();
     input_fd_mutex = dr_mutex_create();
     fn_parser_mutex = dr_mutex_create();

     log_buffer = drx_buf_create_trace_buffer(LOG_BUF_SIZE, flush_log_buffer);

     DR_ASSERT(log_buffer != NULL);

     if (prune_list_libs != NULL) {
	  /* ld seems to always link against client lib's libc, so if
	   * we only rely on dynamorio's module/libray iterator we
	   * will not find the base address for libc that was loaded
	   * for the client.  Thus we use dl_iterate_phdr to iterate
	   * through all loaded libraries, not just those loaded for
	   * the target application
	   */
	  init_prune_list();

     }
     dr_log(NULL, DR_LOG_ALL, 1, "Client 'memcalltrace' initializing\n");
}
