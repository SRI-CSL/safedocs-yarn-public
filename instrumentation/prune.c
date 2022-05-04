/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2022 Narf Industries LLC */
/* This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074. */
#include "prune.h"
#include <string.h>

app_pc *prune_list = NULL;
char *prune_list_libs = NULL;
char *prune_list_contents = NULL;
size_t prune_list_alloc_size = 0;
void *prune_list_mutex = NULL;
char *libc_name = NULL;

void
update_prune_list(const module_data_t *mod, const char *known_basename,
		  app_pc mod_offset)
{
     const char sep[2] = ",";
     char *token, *last, *tmp, *path = NULL;
     const char *lib_basename;
     bool found = false, exists = false, start_found = false;
     char *libc_altname = "libc.so";
     app_pc *tmp_list, last_addr = 0, start_addr = 0, last_copied = 0;
     size_t len, path_len, num_entries = 0;
     size_t lib_idx = -1, token_idx = 0, skip_entries = 0, old_i = 0;
     size_t copy_i = 0, token_i = 0, start_copy = prune_list_alloc_size;

     /* calculate basename of module to see if it matches any entry in
	provided prune list (PRUNE_LIST_LIBS) */
     if (mod) {
	  /* If we have module_data_t, copy module path to temporary
	     buffer and calculate basename */
	  path_len = strlen(mod->full_path);
	  path = dr_global_alloc(path_len + 1);
	  DR_ASSERT(path != NULL);
	  strncpy(path, mod->full_path, path_len);
	  lib_basename = basename(path);
     } else {
	  /* If known_basename is passed it, it is passed in from modules
	   * iterated via dl_iterate_phdr.  Unfortunately, it doesn't
	   * resolve the name of libc in the same manner as dynamorio's
	   * module iterator, so if we come across a known_basename that
	   * begins with 'libc.so' we should instead use the "normal"
	   * libc name set via an environmental variable
	   */
	  path_len = strlen(libc_altname);
	  path = dr_global_alloc(path_len + 1);
	  DR_ASSERT(path != NULL);
	  strncpy(path, known_basename, path_len);
	  if (libc_name && strncmp(libc_altname, path, path_len) == 0) {
	       lib_basename = libc_name;

	  } else {
	       lib_basename = known_basename;
	  }
     }
     /* free temporary space used to calculate basename */
     dr_global_free(path, path_len);

     /* go through provided PRUNE_LIST_LIBS, which is a list in the form of:
      * <library base name>,<number entries in prune list>,
      * and find entry matching
      * current module. If match is found, save abs addr of module.
      * Also save module index (index of corresponding entry in
      * PRUNE_LIST_LIBS), index of first prune entry for module
      * (calculated as PRUNE_LIST_LIBS is traversed while looking
      * for match), and entry's stated number of prune entries. Use
      * prune_list_mutex because strtok modifies the global
      * prune_list_libs string. */
     dr_mutex_lock(prune_list_mutex);
     len = strlen(prune_list_libs);
     last = &prune_list_libs[len];
     token = strtok(prune_list_libs, sep);
     while(token) {
	  if (0 == (token_idx & 0x1)) {
	       /* tokens with even index are module basenames */
	       if(strncmp(token, lib_basename, path_len) == 0) {
		    /* every other token in list is module basename */
		    lib_idx = token_idx / 2;
		    found = true;
		    if (mod) {
			 mod_offset = mod->start;
		    }
	       }
	  } else {
	       /* tokens with odd index state number of entries in
		* prune list correspond to previously specified
		* module */
	       num_entries = strtoull(token, NULL, 10);
	       DR_ASSERT(num_entries >= 0);
	       if (found) {
		    break;
	       }
	       /* add previous module's number of entries to keep track of
		where next module's entry starts */
	       skip_entries += num_entries;
	  }

	  /* strtok replaces sep with 0, restore separator */
	  /* so we can use strtok again against this string */
	  if(&(token[strlen(token)]) < last) {
	       token[strlen(token)] = ',';
	  }

	  token = strtok(NULL, sep);
	  token_idx++;
     }
     /* strtok replaces sep with 0, restore separator */
     /* so we can use strtok again against this string */
     if(token && &(token[strlen(token)]) < last) {
	  token[strlen(token)] = ',';
     }
     /* if current module not in prune list, we are done */
     if (!found) {
	  goto quit_update;
     }
     /* its safe to release lock while allocating space for tmp_list */
     dr_mutex_unlock(prune_list_mutex);
     /* allocate enough space to store entries of current prune list
      * as well as entries we are about to add */
     tmp_list = dr_global_alloc(sizeof(app_pc) * (num_entries +
						  prune_list_alloc_size));
     /* reacquire lock until we are done */
     dr_mutex_lock(prune_list_mutex);
     len = strlen(prune_list_contents);
     last = &prune_list_contents[len];
     /* iterate through prune list, which is list of virtual address
      * until we find the first entry (should be lowest virtual address)
      * for current module
      */
     token = strtok(prune_list_contents, sep);
     DR_ASSERT(token != NULL);
     for (; token_i < skip_entries; token_i++) {
	  if(&(token[strlen(token)]) < last) {
	       token[strlen(token)] = ',';
	  }
	  token = strtok(NULL, sep);
	  DR_ASSERT(token != NULL);
     }
     /* calculate the lowest absolute prune address for module */
     start_addr = (app_pc) ((size_t) strtoull(token, NULL, 0) + mod_offset);
     /* if we already have entries in current prune list, we want to
      make sure the current library does not have any entries at
      current absolute address.  We also want to maintain sorting of
      addresses, so copy entries into */
     if (prune_list) {
	  /* check if we already have entries for this library and
	   * calculate index of where new entries should be added in
	   * order to maintain sorting */
	  for (int i = 0; i < prune_list_alloc_size; i++) {
	       if (prune_list[i] == start_addr) {
		    /* entries for module at this address already
		     * exists, we are done */
		    exists = true;
		    dr_global_free(tmp_list,
				   (sizeof(app_pc) * num_entries) +
				   prune_list_alloc_size);
		    goto quit_update;
	       } else if (!start_found && start_addr < prune_list[i]) {
		    start_copy = i;
		    start_found = true;
		    break;
	       }
	  }
	  /* copy old elements into new list, maintaining sorting */
	  while (old_i < start_copy)  {
	       last_addr = prune_list[old_i];
	       /* make sure list we are forming is sorted */
	       DR_ASSERT(last_addr > last_copied);
	       last_copied = last_addr;
	       tmp_list[copy_i++] = last_copied;
	       DR_ASSERT(last_copied > 0);
	       old_i++;
	  }
     }
     /* copy absolute value of prune addresses for current module into
      * prune list */
     for (size_t i = 0; i < num_entries; i++) {
	  DR_ASSERT(token != NULL);
	  if(&(token[strlen(token)]) < last) {
	       token[strlen(token)] = ',';
	  }
	  last_addr = (app_pc) ((size_t) strtoull(token, NULL, 0) + mod_offset);
	  /* make sure list we are forming is sorted */
	  DR_ASSERT(last_addr > last_copied);
	  last_copied = last_addr;
	  tmp_list[copy_i++] = last_copied;
	  token = strtok(NULL, sep);
     }

     if(token && &(token[strlen(token)]) < last) {
	  token[strlen(token)] = ',';
     }
     /* if there were existing entries in prune_list, copy all values
      * with higher addreses then current module after entries from
      * module */
     if (prune_list) {
	  while(old_i < prune_list_alloc_size)  {
	       last_addr = prune_list[old_i];
	       /* make sure list we are forming is sorted */
	       DR_ASSERT(last_addr > last_copied);
	       last_copied = last_addr;
	       tmp_list[copy_i++] = last_copied;
	       old_i++;
	  }
	  /* we are now done with old prune_list, will be replaced by
	   * tmp_list, so free it */
	  dr_global_free(prune_list, sizeof(app_pc) * prune_list_alloc_size);
     }
     /* increment allocated size by number of entries we just added */
     prune_list_alloc_size += num_entries;
     prune_list = tmp_list;

quit_update:
     dr_mutex_unlock(prune_list_mutex);

}

static int
dl_walk_callback(struct dl_phdr_info *info, size_t size, void *data)
{
     module_data_t *mod;
     update_prune_list(NULL, info->dlpi_name, (app_pc) info->dlpi_addr);
     return 0;
}

void
init_prune_list()
{
    dl_iterate_phdr(dl_walk_callback, NULL);
}

bool
addr_in_prune_list(app_pc addr)
{
     size_t mid = prune_list_alloc_size / 2;
     size_t start = 0, end = prune_list_alloc_size;
     app_pc entry;
     mid = prune_list_alloc_size / 2;
     /* perform binary search on sorted list */
     while (mid >= 0 && mid < prune_list_alloc_size) {
	  entry = prune_list[mid];

	  if (entry == addr) {
	       return true;
	  } else if (entry < addr) {
	       start = mid + 1;
	  } else {
	       end = mid - 1;
	  }
	  mid = start + ((end - start) / 2);
     }
     return false;
}
