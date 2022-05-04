/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _MEM_TRACE_H
#define _MEM_TRACE_H
#include "dr_api.h"
extern bool verbose;
extern char *parser_input_path;
extern bool foptrace;
extern bool sockettrace;
extern bool filewritetrace;
extern int tls_idx;
extern size_t file_offset_trigger;
extern bool file_offset_watchpoint;
extern bool log_on_at_main;
extern bool log_all_calls;
extern bool calltrace;
extern bool instrace;
extern client_id_t client_id;

#endif
