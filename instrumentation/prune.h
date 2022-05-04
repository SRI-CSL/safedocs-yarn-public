/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _MEMTRACE_PRUNE_H
#define _MEMTRACE_PRUNE_H
#define _GNU_SOURCE

#include "dr_api.h"
#include <link.h>


extern app_pc *prune_list;
extern char *prune_list_libs;
extern char *prune_list_contents;
extern size_t prune_list_alloc_size;
extern void *prune_list_mutex;
extern char *libc_name;


void update_prune_list(const module_data_t *mod, const char *known_basename,
		       app_pc mod_offset);
void init_prune_list();

bool addr_in_prune_list(app_pc addr);

#endif
