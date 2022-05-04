/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include "mem-trace.h"
#include "syscall.h"
#include "per-thread.h"
#include "recording-utils.h"
#include "logging.h"
#include "inputfd.h"
#include <syscall.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include "drmgr.h"


static inline void
pre_syscall_handle_recv(void *drcontext, int sysnum)
{
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     data->syscall_fd = (int) dr_syscall_get_param(drcontext, 0);
     data->syscall_addr = (void *) dr_syscall_get_param(drcontext, 1);
}

static inline void
pre_syscall_handle_recvmsg(void *drcontext, int sysnum)
{
     per_thread_mem_t *data;
     struct msghdr *msg = (struct msghdr *) dr_syscall_get_param(drcontext, 1);
     data = drmgr_get_tls_field(drcontext, tls_idx);
     data->syscall_fd = (int) dr_syscall_get_param(drcontext, 0);
     data->iovec_len = msg->msg_iovlen;
     data->iovec = msg->msg_iov;
}

static inline void
pre_syscall_handle_close(void *drcontext, int sysnum)
{
     per_thread_mem_t *data;
     data = drmgr_get_tls_field(drcontext, tls_idx);
     data->syscall_fd = (int) dr_syscall_get_param(drcontext, 0);
}


static inline void
pre_syscall_handle_mmap(void *drcontext, int sysnum)
{
     per_thread_mem_t *data;
     data = drmgr_get_tls_field(drcontext, tls_idx);
     data->syscall_mmap_logged = false;
     data->syscall_flags = (int) dr_syscall_get_param(drcontext, 3);
     data->syscall_fd = (int) dr_syscall_get_param(drcontext, 4);
     data->syscall_offset = (off_t) dr_syscall_get_param(drcontext, 5);
     if(! (data->syscall_flags &MAP_ANONYMOUS)) {
	  if (input_opened && (is_open_inputfd(data->syscall_fd))) {
	       /* input file is being mapped */
	       data->syscall_mmap_logged = true;
	       if (verbose) {
		    dr_printf("input file mmapd\n");
	       }
	       data->syscall_addr = (void *) dr_syscall_get_param(drcontext, 0);
	       data->syscall_len = (size_t) dr_syscall_get_param(drcontext, 1);

	  }
     }
}


static inline void
pre_syscall_handle_munmap(void *drcontext, int sysnum)
{
     per_thread_mem_t *data;
     data = drmgr_get_tls_field(drcontext, tls_idx);
     data->syscall_addr = (void *) dr_syscall_get_param(drcontext, 0);
     data->syscall_len = (size_t) dr_syscall_get_param(drcontext, 1);
}


static inline void
pre_syscall_handle_read(void *drcontext, int sysnum)
{
     per_thread_mem_t *data;
     int fd;
     fd = (int) dr_syscall_get_param(drcontext, 0);
     if (input_opened && is_open_inputfd(fd)) {
	  data = drmgr_get_tls_field(drcontext, tls_idx);
	  data->syscall_fd = fd;
	  data->syscall_addr = (void *) dr_syscall_get_param(drcontext, 1);
	  data->syscall_len = (size_t) dr_syscall_get_param(drcontext, 2);
	  if (sysnum == SYS_pread64) {
	       /* offset included in call */
	       data->syscall_offset = (size_t) dr_syscall_get_param(drcontext,
								    3);
	  } else {
	       /* lookup current offset */
	       data->syscall_offset = lseek(data->syscall_fd, 0, SEEK_CUR);
	  }
     }
}


static inline void
pre_syscall_handle_write(void *drcontext, int sysnum)
{
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     data->syscall_len = (size_t) dr_syscall_get_param(drcontext, 2);
     int fd = (int) dr_syscall_get_param(drcontext, 0);
     if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
	  if (data->syscall_len > 0) {
	       data->syscall_fd = fd;
	       data->syscall_addr = (void *) dr_syscall_get_param(drcontext, 1);
	  }
     } else {
	  data->syscall_len = 0;
     }
}

static inline void
post_syscall_handle_recv(void *drcontext, dr_mcontext_t *mc, int sysnum,
			 log_entry_t *log)
{
     per_thread_mem_t *data;
     /* if recv succeeded */
     if (dr_syscall_get_result(drcontext) != -1) {
	  data = drmgr_get_tls_field(drcontext, tls_idx);
	  log->kind = IS_SOCK_RECV;
	  log->u.sock.sockfd = data->syscall_fd;
	  log->u.sock.addr = data->syscall_addr;
	  log->u.sock.count = (size_t) dr_syscall_get_result(drcontext);
	  copy_log_entry_to_buf(drcontext, log);
     }
     data->syscall_fd = 0;
     data->syscall_addr = 0;
}

static inline void
post_syscall_handle_recvmsg(void *drcontext, dr_mcontext_t *mc, int sysnum,
			    log_entry_t *log)
{
     per_thread_mem_t *data;
     struct iovec *tmp;
     size_t len, recv_count = 0, total_recv = dr_syscall_get_result(drcontext);
     /* if recvmsg succeeded */
     if (total_recv != -1) {
	  data = drmgr_get_tls_field(drcontext, tls_idx);
	  log->kind = IS_SOCK_RECV;
	  log->u.sock.sockfd = data->syscall_fd;
	  tmp = data->iovec;
	  for (size_t i = 0; i < data->iovec_len && (recv_count < total_recv);
	       i++) {
	       len = tmp[i].iov_len;
	       log->u.sock.addr = tmp[i].iov_base;
	       log->u.sock.count = (recv_count + len) <= total_recv ? tmp[i].iov_len : total_recv - recv_count;
	       copy_log_entry_to_buf(drcontext, log);
	  }
     }
     data->iovec = NULL;
     data->iovec_len = 0;
}

static inline void
post_syscall_handle_mmap(void *drcontext, dr_mcontext_t *mc, int sysnum,
			 log_entry_t *log)
{
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     void *result;
     bool ok;
     if (data->syscall_mmap_logged) {
	  data->syscall_mmap_logged = false; /* reset flag */
	  ok = dr_get_mcontext(drcontext, mc);
	  DR_ASSERT(ok);
	  result = (void *) dr_syscall_get_result(drcontext);
	  if (verbose) {
	       dr_printf("-mmap result %p\n", result);
	  }
	  log->kind = IS_FILE_OP;
	  log->u.fop.fd = data->syscall_fd;
	  log->u.fop.kind = FILE_MMAP;
	  log->u.fop.pc = mc->pc;
	  copy_log_entry_to_buf(drcontext, log);

	  log->kind = IS_MMAP;
	  log->u.mmap.addr = result;
	  log->u.mmap.length = data->syscall_len;
	  log->u.mmap.offset = data->syscall_offset;
	  copy_log_entry_to_buf(drcontext, log);
     }

}

static inline void
post_syscall_handle_open(void *drcontext, dr_mcontext_t *mc, int sysnum,
			 log_entry_t *log)
{
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     int fd;
     bool ok;
     if (data->syscall_input_just_opened) {
	  data->syscall_input_just_opened = false; // reset flag
	  fd = (int) dr_syscall_get_result(drcontext);
	  ok = dr_get_mcontext(drcontext, mc);
	  DR_ASSERT(ok);
	  log->kind = IS_FILE_OP;
	  log->u.fop.kind = FILE_OPEN;
	  log->u.fop.pc = mc->pc;
	  log->u.fop.fd = fd;
	  add_inputfd(fd);
	  copy_log_entry_to_buf(drcontext, log);
     }

}

static inline void
post_syscall_handle_close(void *drcontext, dr_mcontext_t *mc, int sysnum,
			  log_entry_t *log)
{
     /* check if input file is being closed */
     bool ok;
     if (input_opened) {
	  per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
	  if (is_open_inputfd(data->syscall_fd)) {
	       if (verbose) {
		    dr_printf("input file is being closed\n");
	       }
	       ok = dr_get_mcontext(drcontext, mc);
	       DR_ASSERT(ok);
	       log->kind = IS_FILE_OP;
	       log->u.fop.fd = data->syscall_fd;
	       log->u.fop.pc = mc->pc;
	       log->u.fop.kind = FILE_CLOSE;

	       remove_inputfd(data->syscall_fd);
	       copy_log_entry_to_buf(drcontext, log);

	  }
     }
}

static inline void
post_syscall_handle_munmap(void *drcontext, dr_mcontext_t *mc, int sysnum,
			   log_entry_t *log)
{
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     bool ok = dr_get_mcontext(drcontext, mc);
     DR_ASSERT(ok);

     if (verbose) {
	  dr_printf("munmap %p %ul\n", data->syscall_addr, data->syscall_len);
     }
     log->kind = IS_FILE_OP;
     log->u.fop.pc = mc->pc;
     log->u.fop.fd = 0; /* we don't keep track of this right now */
     log->u.fop.kind = FILE_MUNMAP;
     copy_log_entry_to_buf(drcontext, log);

     log->kind = IS_MMAP;
     log->u.mmap.addr = data->syscall_addr;
     log->u.mmap.length = data->syscall_len;
     log->u.mmap.offset = 0; /* set to 0 if unmapped */
     copy_log_entry_to_buf(drcontext, log);
}

static inline void
post_syscall_handle_read(void *drcontext, dr_mcontext_t *mc, int sysnum,
			 log_entry_t *log)
{
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     int fd = data->syscall_fd;
     bool ok = dr_get_mcontext(drcontext, mc);
     DR_ASSERT(ok);
     /* only log reads from input file */
     if (input_opened && is_open_inputfd(fd)) {
	  if (file_offset_watchpoint) {
	       /* "watchpoint" offset read */
	       if ((data->syscall_offset <=  file_offset_trigger) &&
		   (file_offset_trigger <
		    (data->syscall_offset + data->syscall_len))) {
		    data->file_offset_watchpoint_active = true;
		    /* enable logging if not yet enabled */
		    if (!data->logging_enabled) {
			 dr_printf("READ %lu bytes to %p from offset %lu\n",
				   data->syscall_len, data->syscall_addr,
				   data->syscall_offset);

			 dr_printf("offset: %ul in (%ul, %ul)\n",
				   file_offset_trigger, data->syscall_offset,
				   data->syscall_offset + data->syscall_len);
			 dr_printf("File watchpoint hit at offset %d, enabling logging\n", file_offset_watchpoint);
			 if (log_on_at_main || data->fn_filter_logging_enabled) {
			      set_logging(drcontext, true, mc->pc, log, data);
			 }
		    }
	       } else if (data->logging_enabled) {
                     /* If watchpoint offset not in read chunk of
		      * data, and log off, reenable log*/
		    dr_printf("A new chunk of input file read, disable logging\n",
			      file_offset_watchpoint);
		    data->file_offset_watchpoint_active = false;
		    set_logging(drcontext, false, mc->pc, log, data);
	       }
	  }

	  log->kind = IS_FILE_OP;
	  log->u.fop.pc = (void *) mc->pc;
	  log->u.fop.kind = FILE_READ;
	  log->u.fop.fd = fd;
	  copy_log_entry_to_buf(drcontext, log);

	  log->kind = IS_FILE_READ;
	  log->u.fread.addr = data->syscall_addr;
	  log->u.fread.offset = data->syscall_offset;
	  log->u.fread.count = data->syscall_len;
	  log->u.fread.fd = fd;
	  copy_log_entry_to_buf(drcontext, log);
	  if (verbose) {
	       dr_printf("%p READ %lu bytes to %p from offset %lu\n",
			 mc->pc, log->u.fread.count,
			 log->u.fread.addr, log->u.fread.offset);
	  }

     }
}
static inline void
post_syscall_handle_write(void *drcontext, dr_mcontext_t *mc, int sysnum,
			  log_entry_t *log)
{
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     size_t len = data->syscall_len;

     if (len > 0) {
	  log->kind = IS_FILE_WRITE;
	  log->u.fwrite.index = data->write_idx++;
	  log->u.fwrite.offset = (off_t) ftell(data->write_logf);
	  log->u.fwrite.count = len;
	  log->u.fwrite.fd = data->syscall_fd;
	  copy_log_entry_to_buf(drcontext, log);
	  DR_ASSERT(fwrite(data->syscall_addr, len, 1, data->write_logf) > 0);
     }
}

void
post_syscall(void *drcontext, int sysnum)
{
     log_entry_t log;
     dr_mcontext_t mc = { sizeof(mc), DR_MC_CONTROL /*only need pc*/ };
     void *result;
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     switch (sysnum) {
     case SYS_mmap:
	  post_syscall_handle_mmap(drcontext, &mc, sysnum, &log);
	  break;
     case SYS_openat:
     case SYS_open:
	  post_syscall_handle_open(drcontext, &mc, sysnum, &log);
	  break;
     case SYS_close:
	  post_syscall_handle_close(drcontext, &mc, sysnum, &log);
	  break;
     case SYS_munmap:
	  post_syscall_handle_munmap(drcontext, &mc, sysnum, &log);
	  break;
     case SYS_read:
     case SYS_pread64:
	  post_syscall_handle_read(drcontext, &mc, sysnum, &log);
	  break;
     case SYS_write:
	  post_syscall_handle_write(drcontext, &mc, sysnum, &log);
	  break;
     case SYS_recvfrom:
	  post_syscall_handle_recv(drcontext, &mc, sysnum, &log);
	  break;
     case SYS_recvmsg:
	  post_syscall_handle_recvmsg(drcontext, &mc, sysnum, &log);
	  break;
     }
}

void
pre_syscall_handle_open(void *drcontext, int sysnum)
{
     per_thread_mem_t *data;
     char *path;
     if (sysnum == SYS_open) {
	  path = (char *) dr_syscall_get_param(drcontext, 0);
     } else {
	  path = (char *) dr_syscall_get_param(drcontext, 1);
     }
     if (path && (strcmp(path, parser_input_path) == 0)) {
	  if (verbose) {
	       dr_printf("now opening parser input file\n");
	  }
	  data = drmgr_get_tls_field(drcontext, tls_idx);
	  data->syscall_input_just_opened = true;
     }
}

bool
pre_syscall(void *drcontext, int sysnum)
{
     per_thread_mem_t *data = drmgr_get_tls_field(drcontext, tls_idx);
     switch(sysnum) {
     case SYS_openat:
     case SYS_open:
	  pre_syscall_handle_open(drcontext, sysnum);
	  break;
     case SYS_mmap:
	  pre_syscall_handle_mmap(drcontext, sysnum);
	  break;
     case SYS_munmap:
	  pre_syscall_handle_munmap(drcontext, sysnum);
	  break;
     case SYS_close:
	  pre_syscall_handle_close(drcontext, sysnum);
	  break;
     case SYS_read:
     case SYS_pread64:
	  pre_syscall_handle_read(drcontext, sysnum);
	  break;
     case SYS_write:
	  pre_syscall_handle_write(drcontext, sysnum);
	  break;
     case SYS_readv:
	  dr_fprintf(STDERR, "do not know how to handle vread syscall yet\n");
	  DR_ASSERT(false);
	  break;
     case SYS_recvmsg:
	  pre_syscall_handle_recvmsg(drcontext, sysnum);
	  break;
     case SYS_recvfrom:
	  pre_syscall_handle_recv(drcontext, sysnum);
	  break;
     case SYS_recvmmsg:
	  dr_fprintf(STDERR, "do not know how to handle recvmmsg syscall yet\n");
	  DR_ASSERT(false);
	  break;
     }
     /* always continue to execute syscall */
     return true;
}


bool
syscall_filter(void *drcontext, int sysnum)
{
     switch (sysnum) {
     case SYS_mmap:
     case SYS_munmap:
     case SYS_open:
     case SYS_openat:
     case SYS_read:
     case SYS_readv:
     case SYS_pread64:
     case SYS_close:
	  return foptrace;
     case SYS_write:
	 return filewritetrace;
     case SYS_recvmsg:
     case SYS_recvmmsg:
     case SYS_recvfrom:
	  return sockettrace;
     default:
	  return false;
     }
}
