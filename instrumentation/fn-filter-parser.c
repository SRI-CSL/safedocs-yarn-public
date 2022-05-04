/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>
#include <errno.h>
#include "dr_api.h"
#include "fn-filter-parser.h"

#define SUCCESS 0

FILE *fn_file = NULL;
char *is_addr_regexp = "0x[a-fA-F0-9]+";
regex_t fn_regex;


int fn_filter_open(char *f)
{
    int ret;
    fn_file = fopen(f,  "r");
    if (!fn_file) {
	return errno;
    }
    ret = regcomp(&fn_regex, is_addr_regexp, REG_EXTENDED);
    if(ret == 0) {
	 return SUCCESS;
    } else {
	// failed to compile regex, bail
	if (fn_file) {
	    fclose(fn_file);
	}
	return ret;
    }
}

void fn_filter_mod_load_reset()
{
     if (fn_file)
	  rewind(fn_file);
}
app_pc fn_filter_next(const module_data_t *mod)
{
    app_pc pc;
    char *line;
    char *end;
    size_t len = 0;
    ssize_t read;
    int regex_res;
    read = getline(&line, &len, fn_file);
    if (read < 1)
	return NULL;
    line[read-1] = '\0'; //replace newline with null

    // check if line contains an address
    regex_res = regexec(&fn_regex, line, 0, NULL, 0);
    if (regex_res != REG_NOMATCH) {
	pc = (app_pc) strtoull(line, &end, 16);
	if (!end) {
	    return (app_pc) FN_FILTER_NEXISTS;
	}
    } else {
	// we must lookup addr of symbol against current module
	pc = (app_pc) dr_get_proc_address(mod->handle, line);
	if (pc) {
	     dr_printf("starting tracking at %s (%p) in %s\n", line, pc, mod->full_path);
	}
    }
    free((void *)line);
    return pc;
}

void fn_filter_close()
{
    fclose(fn_file);
    fn_file = NULL;
}
