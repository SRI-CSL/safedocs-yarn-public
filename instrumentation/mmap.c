/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include "mem-trace.h"
#include "utils.h"
#include "logging.h"
#include "dr_api.h"
#include <string.h>
#include <unistd.h>

/* make copy of proc memory map information.
 * this only needs to be done once
 */
void *mmap_mutex; /* make sure only one thread makes mmap file */

void
save_mmap(void *drcontext)
{
     char mmap_formatted[MAXIMUM_PATH];
     char *mmap = "/proc/%d/maps";
     pid_t id = getpid();
     char c;
     FILE *mmap_FILE, *out_FILE;
     file_t out_file;
     dr_mutex_lock(mmap_mutex);

     snprintf(mmap_formatted, MAXIMUM_PATH, mmap, id);
     mmap_FILE = fopen(mmap_formatted, "r");
     DR_ASSERT(mmap_FILE != NULL);
     out_file = log_file_open(client_id, NULL, logdir, "mmap",
#ifndef WINDOWS
			      DR_FILE_CLOSE_ON_FORK |
#endif
			      DR_FILE_ALLOW_LARGE);
     out_FILE = log_stream_from_file(out_file);
     while ((c = getc(mmap_FILE)) != EOF) {
	  putc(c, out_FILE);
     }
     fclose(mmap_FILE);
     log_stream_close(out_FILE);
     if (verbose) {
	  dr_printf("done copying mmap\n");
     }
     dr_mutex_unlock(mmap_mutex);
}
