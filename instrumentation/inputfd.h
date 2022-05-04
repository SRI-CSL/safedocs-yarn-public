/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _MEMTRACE_INPUTFD_H
#define _MEMTRACE_INPUTFD_H
#include "dr_api.h"

/* make sure only one thread at a time chances input_fd information */
extern void *input_fd_mutex;

/* allow for input fd to be opened multiple times */
#define MAX_INPUT_FDS 10
extern int input_fd[MAX_INPUT_FDS];
extern bool input_opened;

bool remove_inputfd(int fd);
bool add_inputfd(int fd);
bool is_open_inputfd(int fd);
#endif
