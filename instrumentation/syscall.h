/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#ifndef _MEMTRACE_SYSCALL_H
#define _MEMTRACE_SYSCALL_H
#include "dr_api.h"
bool pre_syscall(void *drcontext, int sysnum);
void post_syscall(void *drcontext, int sysnum);
bool syscall_filter(void *drcontext, int sysnum);
#endif
