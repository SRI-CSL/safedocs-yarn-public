/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _FN_FILTER_PARSER
#define _FN_FILTER_PARSER

#define FN_FILTER_NEXISTS 1

int fn_filter_open(char *f);
app_pc fn_filter_next(const module_data_t *mod);
void fn_filter_close();
void fn_filter_mod_load_reset();


#endif
