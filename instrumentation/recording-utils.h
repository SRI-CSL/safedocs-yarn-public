/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _RECORDING_UTILS_H
#define _RECORDING_UTILS_H
#include <stdio.h>
#include "dr_api.h"

void log_memtrace(void *pc, void *addr, unsigned long long value, int type,
		  unsigned short size, int thread, FILE *out);
void log_pc(void *pc, int thread, FILE *out);
void log_callret(void *pc, void *target, void *sp, int kind, int thread,
		 FILE *out);
void log_malloc(void *pc, void *addr, size_t num, int kind, int thread,
		FILE *out);
/* void log_regvalue(void *pc, unsigned int reg, unsigned long long value, */
/* 		  int kind, int thread, FILE *out); */

void log_fread(void *addr, off_t offset, size_t count, int fd, int thread,
	       FILE *out);
void log_fop(void *pc, int fd, int kind, int thread, FILE *out);
void log_mmap(void *addr, size_t len, off_t offset, int kind, int thread,
	      FILE *out);


typedef struct __attribute__((__packed__)) _mem_ref_t {
     void * addr; /* mem ref addr or instr pc */
     void * pc; /* mem ref addr or instr pc */
     unsigned long long value; /* if Read, value is value read. Else value is value at addres *before* it is written */
     unsigned short type; /* r(0), w(1), or opcode (assuming 0/1 are invalid opcode) */
     unsigned short size; /* mem ref size or instr length */
} mem_ref_t;


typedef struct __attribute__((__packed__)) _reg_ref_t {
     void * pc;
     unsigned long long value;
     unsigned int reg;
     unsigned short type;
     char padd[6];
} reg_ref_t;

typedef struct __attribute__((__packed__)) _call_ref_t {
     void * target_addr;
     void * pc;
     void * stack_pointer;
     int kind;
} call_ref_t;

typedef struct __attribute__((__packed__)) _malloc_ref_t {
     void * addr;
     void * pc;
     size_t num_bytes;
     int kind;
} malloc_ref_t;

typedef struct __attribute__((__packed__)) _ins_ref_t {
     void *pc;
     void *rax;
     bool regs_saved;
     char padd[11];
} ins_ref_t;

typedef struct __attribute__((__packed__)) _sig_ref_t {
     void *pc;
     int sig;
     char padd[16];
} sig_ref_t;


typedef struct __attribute__ ((__packed__)) _mmap_op_t {
     void *addr;
     size_t length;
     off_t offset; // set to 0 if unmapped
     char padd[4];
} mmap_op_t;


typedef struct __attribute__ ((__packed__)) _file_op_t {
     void *pc;
     int fd;
     int kind;
     char padd[12];
} file_op_t;

enum {
     FILE_OPEN = 0,
     FILE_CLOSE,
     FILE_READ,
     FILE_MMAP,
     FILE_MUNMAP,
};

typedef struct __attribute__ ((__packed__)) _file_read_t {
     void *addr;
     off_t offset;
     size_t count;
     int fd;
} file_read_t;


typedef struct __attribute__ ((__packed__)) _file_write_t {
     unsigned long long index;
     off_t offset;
     size_t count;
     int fd;
} file_write_t;


typedef struct __attribute__ ((__packed__)) _sock_recv_t {
     void *addr;
     size_t count;
     int sockfd;
     char padd[8];
} sock_recv_t;


union mem_call {
     call_ref_t call;
     mem_ref_t mem;
     malloc_ref_t malloc;
     ins_ref_t ins;
     reg_ref_t reg;
     mmap_op_t mmap;
     file_op_t fop;
     file_read_t fread;
     sig_ref_t sig;
     sock_recv_t sock;
     file_write_t fwrite;
};

enum {
     IS_CALL = 0,
     IS_MEM_REF,
     IS_MALLOC,
     IS_INS,
     IS_REG_VAL,
     IS_MMAP,
     IS_FILE_OP,
     IS_FILE_READ,
     IS_SIG,
     IS_SOCK_RECV,
     IS_FILE_WRITE,
     IS_KIND_MAX,
};

enum {
     SET_LOG_OFF = -2,
     SET_LOG_ON,
};

enum {
     INDIRECT = 0,
     CALL,
     RETURN,
     INDIRECT_JMP,
     NONE = 0xff
};


enum {
     MALLOC_MALLOC = 0,
     MALLOC_CALLOC,
     MALLOC_REALLOC,
     MALLOC_REALLOCARRAY,
     MALLOC_FREE,
     MALLOC_REALLOC_FREE,
     MALLOC_REALLOCARRAY_FREE,
};


enum {
     REF_TYPE_READ = 0,
     REF_TYPE_WRITE = 1,
};


typedef struct  __attribute__((__packed__)) _log_entry_t {
     union mem_call u;
     int kind;
} log_entry_t;

void write_log(log_entry_t *log, FILE *out);
#endif
