/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _MEMTRACE_FNWRAP_H
#define _MEMTRACE_FNWRAP_H
#include "dr_api.h"

bool do_wrap(char *fn_name, void *wrap_pre, void *wrap_post,
	     const module_data_t *mod);
void wrap_logging_fns(char *fn_names, bool log_on, const module_data_t *mod);
extern void *fn_parser_mutex;

#endif
