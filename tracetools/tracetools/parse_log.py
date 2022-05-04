#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from struct import Struct, error as struct_error
import heap
import call_stack
from log_entries import CallEntry, MallocEntry, MemEntry, FileOpEntry
from log_entries import FileReadEntry, MmapEntry, entry_kind_map
from results import Results
import log_entries
import file_ops
import os
import global_config as config
import re
import glob
import sys


class Entry():
    size = 32
    kind_struct = Struct("i")

    @classmethod
    def create_entry(cls, b, entry_filter):
        (kind,) = cls.kind_struct.unpack(b[-4:])
        e = entry_kind_map.get(kind, None)
        if e and (not entry_filter or e in entry_filter):
            return e(b)
        return None


class ParseLogException(Exception):
    pass


class MemtraceLog():
    def __init__(self, res=None,
                 filters=None,
                 track_callstack=False,
                 track_heap=False,
                 track_file_ops=False,
                 track_mem=False,
                 track_libraries=None,
                 filter_fn=None,
                 skip_functions=None,
                 track_thread_switch=None,
                 no_binja=None,
                 src_dirs=None,
                 start_at=None,
                 no_track_except=False,
                 longjmp_functions=None,
                 iter_threads=None,
                 yarn_args=None,
                 yarn_args_result_idx=None,
                 binary_output=False,
                 output=None,
                 track_all_libs=False,
                 **kwargs):
        b = "b" if binary_output else ""
        self.output = open(output, f"w{b}") if output else None
        if yarn_args:
            if res is None:
                if yarn_args_result_idx is not None:
                    res = yarn_args.results_obj[yarn_args_result_idx]
                else:
                    res = yarn_args.results_obj
            if no_binja is None and yarn_args.no_binja is not None:
                no_binja = yarn_args.no_binja
            if start_at is None:
                start_at = yarn_args.start_at
            if track_libraries is None:
                track_libraries = yarn_args.include_libs
            if iter_threads is None:
                iter_threads = yarn_args.thread
            if skip_functions is None:
                skip_functions = yarn_args.skip
            if output is None:
                b = "b" if binary_output else ""
                self.output = open(yarn_args.output, f"w{b}") if yarn_args.output \
                    else None
        elif res is None:
            raise ParseLogException("Must instantiate MemtraceLog with "
                                    "either res (ResultsInfo object) or "
                                    "yarn_args set")
        self.print_out = self.output if self.output else sys.stdout
        self.ri = res
        self.filters = filters if filters else ['EntryObj']
        self.track_callstack = track_callstack
        self.track_heap = track_heap
        self.track_file_ops = track_file_ops
        self.track_mem_ops = track_mem
        self.filter_fn = filter_fn
        self.start_at = start_at if start_at else 0
        self.next_thread_cb = track_thread_switch
        self.skip_until = None
        if track_all_libs:
            track_libraries = [os.path.basename(lib)
                               for lib in self.ri.r.parser_info.bins]
        # remove duplicate libraries
        self.track_libraries = set(track_libraries) if track_libraries \
            else set()
        self.binfo = None
        self.no_binja = no_binja if no_binja is not None else True
        self.src_dirs = src_dirs if src_dirs else []
        self.log_counts = [0 for _ in self.ri.logs]
        num_threads = len(self.ri.logs)
        iter_threads = iter_threads if iter_threads \
            else list(range(num_threads))
        not_exist = [i for i in list(iter_threads) if i >= num_threads]
        if not_exist:
            raise ParseLogException("Cannot track non-existent threads"
                                    f" {not_exist}")
        self.iter_threads = iter(iter_threads)
        self.current_log = next(self.iter_threads)

        def open_log(log):
            if log and os.path.exists(log):
                return open(log, "rb")
            else:
                return None
        self.write_logs = [open_log(self.ri.writelogs[i])
                           for i in list(iter_threads)]

        if self.no_binja:
            self._enable_no_binja_bin_info(no_track_except)
        else:
            self._enable_bin_info(no_track_except)

        self.skip_functions = skip_functions if skip_functions else []

        environs = self.ri.result_info.environ
        self.disabled_fns = environs.get(Results.DISABLE_FN_ENVIRON, "")
        self.enabled_fns = environs.get(Results.ENABLE_FN_ENVIRON, "")

        if skip_functions:
            for f in skip_functions:
                self.add_skip_function(f)
        self.longjmp_functions = longjmp_functions if longjmp_functions else []

        if self.track_callstack:
            fns = {i: [f for sublist in
                       [self.binfo.get_fn_addrs_from_name(fn)
                        for fn in getattr(self, f"{i}_fns").split(",") if fn]
                       for f in sublist]
                   for i in ["enabled", "disabled"]}

            # setup per-thread callstack tracker
            self._stack = [call_stack.CallStack(self.binfo,
                                                fns["enabled"],
                                                fns["disabled"],
                                                self.longjmp_functions)
                           for _ in self.ri.logs]
        else:
            self._stack = None
        if self.track_heap:
            self.heap = heap.Heap(self.binfo)
        else:
            self.heap = None
        if self.track_file_ops:
            self.files = file_ops.FileTrackers(self.binfo)
        else:
            self.files = None

        # do sanity check of all entry kinds to make sure they are the
        # correct size
        for k in log_entries.entry_kinds:
            if k.struct_size != Entry.size:
                raise Exception("class %s struct_size must equal %d but is %d"
                                % (k, Entry.size, k.struct_size))
        if 'EntryObj' in self.filters:
            self.filters = log_entries.entry_kinds
        else:
            try:
                self.filters = [getattr(log_entries, i) for i in self.filters]
            except KeyError:
                raise Exception("One of your filters does not correspond to"
                                "existing event type: %s" % self.filters)

    @property
    def log_count(self):
        return self.log_counts[self.current_log]

    def write_entry_log_bytes(self, entry, threadno=None):
        return self.write_log_bytes(entry.offset, entry.count, threadno)

    def write_log_bytes(self, offset, count, threadno=None):
        if threadno is None:
            threadno = self.current_log
        log = self.write_logs[threadno]
        if log:
            log.seek(offset)
            b = log.read(count)
            return b

    @log_count.setter
    def log_count(self, v):
        self.log_counts[self.current_log] = v

    @property
    def stack(self):
        return self._stack[self.current_log] if self._stack else None

    def _enable_bin_info_common(self, suffix, no_except):
        # libcname = re.compile("^libc[-0-9.]*\.so[0-9.]*$")

        # def is_libc(name):
        #     return libcname.match(name)

        # tracking_libc = False
        for lib in list(self.track_libraries):
            # if is_libc(lib):
            #     tracking_libc = True

            l_path = self.ri.get_lib_path(lib)
            if not os.path.isfile(l_path):
                if no_except:
                    return
                raise Exception(f"No such library '{lib}' at {l_path}. "
                                "(Check your -l flag?)")
            bndb = self.ri.get_bin_metadata_path(lib,
                                                 suffix)
            self.binfo.add_library_bv(l_path, bndb)
        # if self.track_callstack and not tracking_libc:
        #     for lib in glob.glob(self.ri.get_lib_path("*")):
        #         if is_libc(os.path.basename(lib)):
        #             self.binfo.add_library_bv(lib, suffix, notrack=True)
        #             break

    def _enable_no_binja_bin_info(self, no_except=False):
        import bin_info_no_binja as not_binja
        if not self.binfo:
            self.binfo = not_binja.BinaryInfo(self.ri.parser_bin,
                                              mmap_file=self.ri.mmap,
                                              ri=self.ri,
                                              src_dirs=self.src_dirs)
            self._enable_bin_info_common(not_binja.BinaryInfo.suffix,
                                         no_except)

    def _enable_bin_info(self, no_except=False):
        import bin_info
        if not self.binfo and not self.no_binja:
            bndb = self.ri.get_bin_metadata_path(self.ri.r.parser_name,
                                                 bin_info.BinaryInfo.suffix)

            self.binfo = bin_info.BinaryInfo(self.ri.parser_bin,
                                             bndb,
                                             mmap_file=self.ri.mmap,
                                             src_dirs=self.src_dirs)
            self._enable_bin_info_common(bin_info.BinaryInfo.suffix, no_except)

    # # this can be called after MemtraceLog() init'd
    # def enable_callstack_tracking(self, callback=True):
    #     self.track_callstack = callback
    #     self._enable_bin_info()
    #     if not self.stack:
    #         self.stack = call_stack.CallStack(self.binfo)

    # def enable_file_op_tracking(self, callback=True):
    #     self.track_file_ops = callback
    #     # self._enable_bin_info()
    #     if not self.files:
    #         self.files = file_ops.FileTrackers(self.binfo)

    # def enable_heap_tracking(self, callback=True):
    #     self.track_heap = callback
    #     self._enable_bin_info()
    #     if not self.heap:
    #         self.heap = heap.Heap(self.binfo)

    def add_skip_function(self, f):
        start = self.binfo.get_fn_addrs_from_name(f)
        if not start:
            raise Exception("cannot filter function %s, "
                            "does not exist" % f)
        print("for %s skipping addrs: %s" %
              (f, [("%x" % a) for a in start]))
        self.skip_functions.extend(start)

    def reset(self, lognum=None):
        lognum = self.current_log if lognum is None else lognum
        self.ri.logs[lognum].seek(0, 0)

    def close(self):
        [log.close() for log in self.ri.logs]
        [log.close() for log in self.write_logs if log]
        if self.binfo:
            self.binfo.close()
        if self.output:
            self.output.close()

    def iter_all(self, log_num=None):
        if log_num is not None:
            self.current_log = log_num
        for i in self:
            pass

    def __iter__(self):
        return self

    def _next(self):
        sz = Entry.size
        f = self.ri.logs[self.current_log]
        filters = self.filters
        while True:  # continue parsing until a struct is returned
            b = f.read(sz)
            try:
                entry = Entry.create_entry(b, filters)
            except struct_error:
                entry = None
                if len(b) == 0:
                    pos = f.tell()
                    f.seek(0, 2)
                    if pos != f.tell():  # if not currently at last byte in file
                        raise ParseLogException("There appears to be missing log "
                                                "data from the file, perhaps it is"
                                                " truncated? Make sure file "
                                                "size is a multiple of %d" % sz)
                    else:
                        # raises StopIteration if no threads left to parse
                        last = self.current_log
                        self.current_log = next(self.iter_threads)
                        if self.next_thread_cb:
                            self.next_thread_cb(self.current_log, last)
                        f = self.ri.logs[self.current_log]
            if entry:
                entry.log_index = self.log_count
                entry.log_num = self.current_log
                self.log_count += 1
                if entry.__class__ in filters:
                    filter_fn = self.filter_fn
                    if filter_fn:
                        if filter_fn(entry, self):
                            return entry
                    else:
                        return entry
            # if nothing was returned yet, continue to parse next log entry

    def iter_entries(self, log_num=None):
        if log_num is not None:
            self.current_log = log_num
        for i in self.__iter__():
            yield i

    def __next__(self):
        o = self._next()
        while self.log_count < self.start_at:
            o = self._next()
        # creating locals for performance reasions
        t_callstack = self.track_callstack
        t_heap = self.track_heap
        t_mem_ops = self.track_mem_ops
        t_f_ops = self.track_file_ops
        skip_fns = self.skip_functions
        while self.skip_until:
            if (o.kind == CallEntry.encoding):
                if o.call_kind == o.RET and o.target_addr == self.skip_until:
                    self.skip_until = None
            o = self._next()
        o_kind = o.kind
        if skip_fns and o_kind == CallEntry.encoding and \
           o.call_kind == o.CALL and o.target_addr in skip_fns:
            seg = self.binfo.get_segment_at(o.pc)
            self.skip_until = self.binfo.next_ip(o.pc, seg)
        if (t_mem_ops or t_f_ops) and (o_kind == MemEntry.encoding):
            if t_f_ops and o.typ == o.WRITE:
                self.files.update(o)
            if callable(t_mem_ops):
                t_mem_ops(o, self)
        elif t_callstack and (o_kind == CallEntry.encoding):
            changed = self.stack.update(o)
            if changed and callable(t_callstack):
                t_callstack(o, self)
        elif t_f_ops and \
             ((o_kind == FileOpEntry.encoding) or
              (o_kind == FileReadEntry.encoding) or
              (o_kind == MmapEntry.encoding)):
            self.files.update(o)
            if callable(t_f_ops):
                t_f_ops(o, self)
        elif t_heap and (o_kind == MallocEntry.encoding):
            e = self.heap.update(o)
            if callable(t_heap):
                t_heap(o, e, self)
        return o
