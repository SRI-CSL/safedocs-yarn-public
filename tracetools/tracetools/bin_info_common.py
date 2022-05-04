# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import mmap_info
import logging
import os
# import logging
import subprocess
from tracetools.signatures.utils import Demangler
import intervaltree as it


class BinInfoException(Exception):
    pass


class NoBinjaBinInfoException(Exception):
    pass


class BinaryInfoCommon():

    def __init__(self, binary, binary_view, mmap_file, src_dirs, bin_dir):
        self.fn_info_cache = {}
        self.bv = binary_view
        self.src_dirs = src_dirs
        self.bin_dir = bin_dir
        self.fn_cache = mmap_info.it.IntervalTree()
        self.binary = binary
        self.mmap = None
        self.src_dirs = src_dirs
        self.binary_name = os.path.basename(self.binary)
        if mmap_file:
            self._parse_mmap_file(mmap_file)
        self.all_bvs = {self.binary_name: self.bv}
        self.lib_bvs = []

    def _parse_mmap_file(self, mmap_file):
        if isinstance(mmap_file, str):
            mmap_file = open(mmap_file, 'r')
        self.mmap = mmap_info.MmapInfo(mmap_file,
                                       self.binary_name)
        self.mmap.parse_file(self.bin_dir)

    def abs_to_virt(self, addr):
        return self.mmap.abs_to_virt(addr)

    def _abs_to_virt(self, addr, segment):
        return self.mmap._abs_to_virt(addr, segment)

    def _virt_to_abs(self, addr, segment):
        return self.mmap._virt_to_abs(addr, segment)

    def get_segment_at(self, addr):
        return self.mmap.segment_at(addr)

    def next_ip(self, ip, seg=None):
        # in case we don't have binja information on this binary/pc
        # assuming call instruction is 5 bytes (x86_64)
        length = 5
        if seg is None:
            seg = self.get_segment_at(ip)
        if seg:
            try:
                length = self.all_bvs[seg.basename].get_instruction_length(
                    self._abs_to_virt(ip, seg)
                )
            except Exception:
                pass
        return ip + length

    def file_line_from_pc(self, offset, binary=None):
        binary = self.binary if not binary else binary
        # based on https://github.com/mechanicalnull/sourcery_pane
        cmd = "addr2line -e %s -a 0x%x -f" % (binary,
                                              offset)
        child = subprocess.Popen(cmd.split(),
                                 stdout=subprocess.PIPE)
        out, err = child.communicate()
        if not isinstance(out, str):
            out = out.decode()
        output_lines = out.split("\n")
        source_line = output_lines[2].strip()  # e.g. "/foo/pngtrans.c:861"
        if source_line.startswith("??") or source_line.endswith("?"):
            return (None, None)
        (src, no) = source_line.rsplit(":", 1)
        no = no.split()[0]  # sometime extra junk is written after lineno
        if not os.path.exists(src):
            # attempt to resolve path based on self.src_dirs
            # find longest common path suffix
            src_split = [s for s in src.split(os.sep) if s]  # remove empty
            for i in self.src_dirs:
                split = [s for s in i.split(os.sep) if s]
                base = split[-1]
                index = 0
                try:
                    index = src_split.index(base)
                except ValueError:
                    continue
                if len(src_split) > index:
                    index += 1
                f = os.path.join(i, os.sep.join(src_split[index:]))
                if os.path.exists(f):
                    src = f
                    break

        return (src, int(no))

    def abs_addr_of_binary(self, name):
        for s in self.mmap.mmap:
            if s.data.basename == name and "x" in s.data.perms:
                return s.data.true_begin
        return None

    # check for all locations of binary
    def abs_addrs_of_lib(self, name):
        libs = []
        for s in self.mmap.mmap:
            if s.data.basename == name and "x" in s.data.perms:
                libs.append(s.data)
        return [lib.true_begin for lib in libs]

    def lib_regions(self, name):
        return it.IntervalTree([s for s in self.mmap.mmap
                                if s.data.basename == name])

    def get_disassembly(self, ip, segment):
        virtip = self._abs_to_virt(ip, segment)
        bv = None
        if segment:
            bv = self.all_bvs.get(segment.basename, None)
            if bv:
                return bv.get_disassembly(virtip)
        return None

    def _add_library_bv(self, path, db_path, create_bv_callback, notrack):
        n = os.path.basename(path)
        if n in self.all_bvs:
            logging.error(f"Already tracking library {n}, "
                          "not adding another instance")
            return
        logging.info("adding tracing for library %s at %s" % (path,
                                                              db_path))
        if not notrack:
            self.mmap.tracked_libs.append(n)
        bv = create_bv_callback()
        self.all_bvs[n] = bv
        self.lib_bvs.append(bv)
        if not notrack:
            self.mmap.add_lib_tracking(n)

    def has_binja(self, seg):
        return False

    def get_binja_tags_at(self, addr, seg=None):
        raise NoBinjaBinInfoException()

    def _get_fn_info_from_name(self, name, typval, anytype, lib):
        all_fns = []
        demangled = Demangler.demangle(name)
        cache_key = (demangled, anytype, lib)
        if cache_key in self.fn_info_cache:
            # make of copy of each item in the list so it is not lost
            cache = [f for f in self.fn_info_cache[cache_key]]
            return cache
        lib_found = False

        for b in [self.bv] + self.lib_bvs:
            k = self.get_binary_view_basename(b)
            if lib is not None and not lib == k:
                continue
            lib_found = True
            r = self.mmap.name_to_region(k)
            # binja sometimes adds "_0" suffix to symbol name
            fns = [(f, r) for f in b.functions
                   if ((anytype and (f.symbol.type != typval)) or
                       (not anytype and (f.symbol.type == typval)))
                   and f.name
                   and demangled == Demangler.demangle(f.name)]
            # if found match, return it, else continue loop
            if fns:
                all_fns += fns
        if lib is not None and not lib_found:
            raise Exception(f"Do not have informaton on the '{lib} binary")
        # make of copy of each item in the list so it is not lost
        self.fn_info_cache[cache_key] = [p for p in all_fns]
        return all_fns

    def _get_fn_addrs_from_name(self, name, typval, find_all):
        demangled = Demangler.demangle(name)
        # first try lookup in binary bv, then try other libs
        fns = []
        for b in [self.bv] + self.lib_bvs:
            rs = self.mmap.name_to_regions(self.get_binary_view_basename(b))
            # binja sometimes adds "_0" suffix to symbol name
            matches = [f for f in b.functions
                       if (((not find_all and f.symbol.type == typval) or
                            (find_all and f.symbol.type != typval)))
                       and f.name
                       and demangled == Demangler.demangle(f.name)]
            for r in rs:
                fns.extend([self._virt_to_abs(f.start, r) for f in matches])
        return fns

    def close(self):
        pass
