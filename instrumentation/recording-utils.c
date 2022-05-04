/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include "recording-utils.h"
void write_log(log_entry_t *log, FILE *out)
{
     fwrite(log, sizeof(log_entry_t), 1, out);
}

void log_memtrace(void *pc, void *addr, unsigned long long value, int type, unsigned short size, int thread, FILE *out)
{
     log_entry_t log;
     log.kind = IS_MEM_REF;
     log.u.mem.addr = addr;
     log.u.mem.pc = pc;
     log.u.mem.value = value;
     log.u.mem.type = type;
     log.u.mem.size = size;
     write_log(&log, out);
}

void log_pc(void *pc, int thread, FILE *out)
{
     log_entry_t log;
     log.kind = IS_INS;
     log.u.ins.pc = pc;
     write_log(&log, out);
}

void log_callret(void *pc, void *target, void *sp, int kind, int thread, FILE *out)
{
     log_entry_t log;
     log.kind = IS_CALL;
     log.u.call.pc = pc;
     log.u.call.target_addr = target;
     log.u.call.stack_pointer = sp;
     log.u.call.kind = kind;
     write_log(&log, out);
}
void log_malloc(void *pc, void *addr, size_t num, int kind, int thread, FILE *out)
{
     log_entry_t log;
     log.kind = IS_MALLOC;
     log.u.malloc.addr = addr;
     log.u.malloc.pc = pc;
     log.u.malloc.kind = kind;
     log.u.malloc.num_bytes = num;
     write_log(&log, out);
}

/* void log_regvalue(void *pc, unsigned int reg, unsigned long long value, int kind, int thread, FILE *out) */
/* { */
/*      log_entry_t log; */

/*      log.kind = IS_REG_VAL; */
/*      log.u.reg.pc = pc; */
/*      log.u.reg.reg = reg; */
/*      log.u.reg.value = value; */
/*      log.u.reg.type = kind; */
/*      write_log(&log, out); */
/* } */

void log_fread(void *addr, off_t offset, size_t count, int fd, int thread, FILE *out)
{
     log_entry_t log;
     log.kind = IS_FILE_READ;
     log.u.fread.addr = addr;
     log.u.fread.offset = offset;
     log.u.fread.count = count;
     log.u.fread.fd = fd;
     write_log(&log, out);
}
void log_fop(void *pc, int fd, int kind, int thread, FILE *out)
{
     log_entry_t log;
     log.kind = IS_FILE_OP;
     log.u.fop.pc = pc;
     log.u.fop.fd = fd;
     log.u.fop.kind = kind;
     write_log(&log, out);
}
void log_mmap(void *addr, size_t len, off_t off, int kind, int thread, FILE *out)
{
     log_entry_t log;
     log.kind = IS_MMAP;
     log.u.mmap.addr = addr;
     log.u.mmap.length = len;
     log.u.mmap.offset = off;
     write_log(&log, out);
}
