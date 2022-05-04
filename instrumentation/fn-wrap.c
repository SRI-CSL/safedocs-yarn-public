/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include "fn-wrap.h"
#include "mem-trace.h"
#include "logging.h"
#include <string.h>
#include "drsyms.h"
#include "drwrap.h"

void *fn_parser_mutex;

typedef struct sym_info {
    char *name;
    size_t name_len;
    size_t offset;
    bool found;
} sym_info_t;

static bool
fn_search_cb(const char *name, size_t modoffs, void *data) {
    sym_info_t *info;
    info = (sym_info_t *) data;
    if ((strlen(name) == info->name_len) &&
	(strncmp(info->name, name, info->name_len) == 0)) {
	info->offset = modoffs;
	info->found = true;
	return false;
    }
    return true;
}


bool
do_wrap(char *fn_name, void *wrap_pre, void *wrap_post, const module_data_t *mod)
{
     app_pc towrap;
     bool ok = false;
     towrap = (app_pc) dr_get_proc_address(mod->handle, fn_name);
     size_t path_len = mod->full_path ? strlen(mod->full_path): 0;
     if ((mod->full_path && towrap == NULL)  &&
	 ((strncmp(".so", mod->full_path + (path_len - 3), 3) != 0))) {
	 sym_info_t info;
	 info.name = fn_name;
	 info.name_len = strlen(fn_name);
	 info.found = false;
	 /* try searching all symbols */
	 drsym_enumerate_symbols(mod->full_path,
				 fn_search_cb,
				 &info, 0);
	 if (info.found) {
	     towrap = info.offset + mod->start;
	 }
     }
     if (towrap != NULL) {
	  ok = drwrap_wrap(towrap, wrap_pre, wrap_post);
	  if (!ok) {
	       dr_fprintf(STDERR,
			  "<FAILED to wrap %s @" PFX
			  ": already wrapped?\n",
			  fn_name, towrap);
	  } else if (verbose) {
	       dr_fprintf(STDOUT, "<wrapped %s @" PFX "\n", fn_name, towrap);
	  }
     }
     return (towrap != NULL) && ok;
}


void
wrap_logging_fns(char *fn_names, bool log_on, const module_data_t *mod)
{
     char *token, *last, *tmp;
     const char sep[2] = ",";
     size_t tok_len, len;
     bool ok = false;
     dr_mutex_lock(fn_parser_mutex);
     tok_len = 0;
     len = strlen(fn_names);
     last = &fn_names[len];
     token = strtok(fn_names, sep);
     while (token) {
	  if (log_on) {
	       /* don't wrap main, it has already been wrapped */
	       if (0 != strncmp(token, "main", 5)) {
		    ok = do_wrap(token, log_on_wrap_pre, log_on_wrap_post, mod);
	       }
	  } else {
	       ok = do_wrap(token, log_off_wrap_pre, log_off_wrap_post, mod);
	  }
	  tok_len = strlen(token);
	  /* strtok replaces sep with 0, restore separator */
	  /* so we can use strtok again against this string */
	  tmp = token;
	  token = strtok(NULL, sep);
	  if(&tmp[tok_len] < last) {
	       tmp[tok_len] = ',';
	  }
	  /* if fn was wrapped */
	  if (ok) { /* then remove from list by replacing chars with
		     * comma separator */
	       for (int i = 0; i < tok_len; i++) {
		    tmp[i] = ',';
	       }
	  }

     }
     dr_mutex_unlock(fn_parser_mutex);
}
