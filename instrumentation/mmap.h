/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _MEMTRACE_MMAP_H
#define _MEMTRACE_MMAP_H

extern void *mmap_mutex; /* make sure only one thread makes mmap file */
void save_mmap(void *drcontext);

#endif
