# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import re
import os
import intervaltree as it
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
import memory_tree # overrides printing style of intervaltree


class Region():
    rxp = re.compile("([a-zA-Z0-9]+)-([a-zA-Z0-9]+) ([rxpw-]{4}) ([a-zA-Z0-9]+)")

    def __init__(self, line: str):
        res = self.rxp.match(line)
        self.begin = int(res.group(1), 16)
        self.end = int(res.group(2), 16)
        self.perms = res.group(3)
        self.offset = int(res.group(4), 16)
        self.true_begin = self.begin  # value of first region for file
        marker = None
        if '/' in line:
            marker = '/'
        elif '[' in line:
            marker = '['
        if marker:
            self.path = line[line.index(marker):].strip()
        else:
            self.path = ''
        self.is_stack = self.path == "[stack]"
        if not self.is_stack:
            self.basename = os.path.basename(self.path)
        else:
            self.basename = ''
        self.is_binary = False
        self.is_tracked = False
        self.segment_num = -1

    def setup(self, bin_name, istracked, segment_num, begin):
        self.segment_num = segment_num
        self.is_binary = self.path.startswith('/') and \
            (self.basename == bin_name)
        self.is_tracked = self.is_binary or istracked
        self.true_begin = begin

    def __repr__(self):
        return "%s (%x-%x)+0x%x/%x/%s/%s" % (self.path, self.begin,
                                             self.end,
                                             self.offset,
                                             self.true_begin,
                                             self.perms,
                                             self.is_tracked)


class MmapInfo():
    addrre = re.compile(
        "[\s]*([0-9a-fA-F]+)-([0-9a-fA-F]+)[\s]+[rwxp-]+[\s]+([0-9a-fA-F]+)"
    )

    def __init__(self, mmapfile, binary_name):
        if isinstance(mmapfile, str):
            mmapfile = open(mmapfile, "r")
        # if isinstance(binary, str):
        #     binary = open(binary, "rb")
        self.tracked_libs = []
        self.mmapfile = mmapfile
        self.binary_name = binary_name
        self.mmap = it.IntervalTree()
        self.loaded_symbol_files = []
        self.parsed = False
        self.regions = []
        self._last_seg = None

    def __repr__(self):
        return "\n".join(["%s: %s" % (i.data, i) for i in self.mmap])

    def segment_at(self, addr):
        if addr is None:
            return
        # fastpath: assume is in last_seg, if not then search
        last = self._last_seg
        if last and (last.begin <= addr) and (addr < last.end):
            return last.data
        segment = self.mmap.at(addr)
        try:
            segment = segment.pop()
            self._last_seg = segment
        except KeyError:
            segment = None
        return segment.data if segment else None

    def abs_to_virt(self, addr):
        segment = self.segment_at(addr)
        return self._abs_to_virt(addr, segment)

    def _abs_to_virt(self, addr, segment):
        if segment:
            return addr - segment.true_begin
        else:
            return addr

    def _virt_to_abs(self, addr, segment):
        if segment:
            return addr + segment.true_begin
        else:
            return addr

    def add_lib_tracking(self, lib):
        n = os.path.basename(lib)
        if n not in self.tracked_libs:
            self.tracked_libs.append(n)
        if self.parsed:
            for i in self.mmap:
                if i.data.basename == n:
                    i.data.is_tracked = True

    def _is_lib_tracked(self, lib):
        return os.path.basename(lib) in self.tracked_libs

    def name_to_region(self, name, perms="x"):
        # return first region with matching name and permissions
        for r in self.regions:
            if r.basename == name and perms in r.perms:
                # return first match
                return r
        return None

    def name_to_regions(self, name, perms="x"):
        # return all regions with matching name and permissions
        regions = []
        for r in self.regions:
            if r.basename == name and perms in r.perms:
                regions.append(r)
        return regions

    def parse_file(self, bin_dir):
        if self.parsed:
            # only perform this step once per instance
            return
        self.mmapfile.seek(0)
        lastpath = None
        # begin = 0
        segment_num = 0
        bin_name = self.binary_name
        # true_begin = False
        seg_true_begin = None
        # prev_seg = None

        def exec_seg_vaddr(reg):
            # go through elf sections to see what stated virtual addr is
            # if it doesn't match begin, then we know that the ELF's
            # segment has been relocated so we use the relocated address
            # instead of 0
            path = os.path.join(bin_dir, reg.basename) \
                if bin_dir and reg.basename else reg.path
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    elf = ELFFile(f)
                    lowest_addr = None
                    for seg in elf.iter_segments():
                        if P_FLAGS.PF_X & seg['p_flags']:
                            vaddr = seg['p_vaddr']
                            lowest_addr = vaddr if lowest_addr is None else \
                                min(vaddr, lowest_addr)

                    return 0 if lowest_addr == r.begin else r.begin
            return r.begin

        for l in self.mmapfile.readlines():
            r = Region(l)
            if not [c for c in ["r", "w", "x"] if c in r.perms]:
                # if there are no r/w/x permissions
                continue
            self.regions.append(r)
            if r.path and r.path == lastpath:
                segment_num += 1
            else:
                seg_true_begin = exec_seg_vaddr(r)
                segment_num = 0
            r.setup(bin_name, self._is_lib_tracked(r.path),
                    segment_num, seg_true_begin)
            self.mmap.add(it.Interval(r.begin, r.end, r))
            lastpath = r.path
        self.parsed = True
        return self.mmap
