/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include "inputfd.h"
void *input_fd_mutex; /* make sure only one thread at a time chances input_fd information */

/* allow for input fd to be opened multiple times */
#define MAX_INPUT_FDS 10
int input_fd[MAX_INPUT_FDS];
bool input_opened = false;

bool
remove_inputfd(int fd)
{
     dr_mutex_lock(input_fd_mutex);
     bool any_open;
     bool closed = false;
     for (int i = 0; i < MAX_INPUT_FDS; i++) {
	  if (input_fd[i]) {
	       any_open = true;
	  }
	  if(input_fd[i] == fd) {
	       input_fd[i] = 0;
	       closed = true;
	  }
     }
     input_opened = any_open;
     dr_mutex_unlock(input_fd_mutex);
     if (!closed) {
	  dr_fprintf(STDERR, "did not find fd in saved input_fd\n");
     }
     return closed;
}

bool
add_inputfd(int fd)
{
     dr_mutex_lock(input_fd_mutex);
     for (int i = 0; i < MAX_INPUT_FDS; i++) {
	  /* find first open slot */
	  if (input_fd[i] == 0) {
	       input_fd[i] = fd;
	       input_opened = true;
	       dr_mutex_unlock(input_fd_mutex);
	       return true;
	  }
     }
     dr_mutex_unlock(input_fd_mutex);
     dr_fprintf(STDERR, "input fd opened too many times, ..cannot track\n");
     DR_ASSERT(false);
     return false;
}

bool
is_open_inputfd(int fd)
{
     dr_mutex_lock(input_fd_mutex);
     for (int i = 0; i < MAX_INPUT_FDS; i++) {
	  if (input_fd[i] && (input_fd[i] == fd)) {
	       dr_mutex_unlock(input_fd_mutex);
	       return true;
	  }
     }
     dr_mutex_unlock(input_fd_mutex);
     return false;
}
